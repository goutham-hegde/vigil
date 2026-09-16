import clsx from 'clsx'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { clock, clockShort, LAYER_LABEL, LAYERS, num, THREAT_LABEL } from '../lib/format'
import type { Explanation, SeriesPoint } from '../lib/types'
import { layerColorVar } from './ui'

function useWidth<T extends HTMLElement>() {
  const ref = useRef<T>(null)
  const [width, setWidth] = useState(0)
  useEffect(() => {
    if (!ref.current) return
    const ro = new ResizeObserver(([entry]) => setWidth(entry.contentRect.width))
    ro.observe(ref.current)
    return () => ro.disconnect()
  }, [])
  return [ref, width] as const
}

function niceMax(v: number) {
  if (v <= 0) return 10
  const exp = 10 ** Math.floor(Math.log10(v))
  const f = v / exp
  const step = f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10
  return step * exp
}

function Tooltip({ x, y, width, children }: { x: number; y: number; width: number; children: ReactNode }) {
  const left = Math.min(Math.max(x + 12, 0), Math.max(0, width - 196))
  return (
    <div
      role="status"
      className="pointer-events-none absolute z-10 w-[184px] rounded-lg border border-line bg-surface/95 p-2.5 text-xs shadow-pop backdrop-blur"
      style={{ left, top: y }}
    >
      {children}
    </div>
  )
}

function TipRow({ color, label, value, dashed }: { color?: string; label: string; value: string; dashed?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3 py-0.5">
      <span className="flex items-center gap-1.5 text-ink-3">
        {color && (
          <span
            className="h-0.5 w-3 rounded-full"
            style={dashed ? { borderTop: `2px dotted ${color}` } : { background: color }}
          />
        )}
        {label}
      </span>
      <span className="tnum font-semibold text-ink">{value}</span>
    </div>
  )
}

export function Legend({ items }: { items: { label: string; color: string; shape?: 'dot' | 'bar' }[] }) {
  return (
    <ul className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-ink-2">
      {items.map((i) => (
        <li key={i.label} className="flex items-center gap-1.5">
          <span
            className={i.shape === 'dot' ? 'size-2 rounded-full' : 'h-2.5 w-2.5 rounded-[3px]'}
            style={{ background: i.color }}
          />
          {i.label}
        </li>
      ))}
    </ul>
  )
}

/** Events per simulated minute, stacked by telemetry layer. */
export function ActivityChart({ data, height = 220 }: { data: SeriesPoint[]; height?: number }) {
  const [ref, width] = useWidth<HTMLDivElement>()
  const [hover, setHover] = useState<number | null>(null)
  const pad = { top: 14, right: 8, bottom: 22, left: 40 }
  const slots = 60
  const points = data.slice(-slots)
  const innerW = Math.max(0, width - pad.left - pad.right)
  const innerH = height - pad.top - pad.bottom
  const band = innerW / slots
  const barW = Math.max(2, Math.min(24, band - 2))
  const max = niceMax(Math.max(1, ...points.map((p) => p.network + p.endpoint + p.application)))
  const y = (v: number) => pad.top + innerH - (v / max) * innerH
  const ticks = [0, max / 2, max]
  const offset = slots - points.length
  const hovered = hover !== null ? points[hover] : null

  return (
    <div ref={ref} className="relative" onPointerLeave={() => setHover(null)}>
      {width > 0 && (
        <svg width={width} height={height} role="img" aria-label="Events per minute by telemetry layer">
          {ticks.map((t) => (
            <g key={t}>
              <line x1={pad.left} x2={width - pad.right} y1={y(t)} y2={y(t)} stroke={t === 0 ? 'var(--color-axis)' : 'var(--color-grid)'} />
              <text x={pad.left - 8} y={y(t)} dy="0.32em" textAnchor="end" className="tnum fill-ink-3 text-[10px]">
                {num(t)}
              </text>
            </g>
          ))}
          {points.map((p, i) => {
            const x = pad.left + (offset + i) * band + (band - barW) / 2
            let acc = 0
            const segs = LAYERS.filter((l) => p[l] > 0)
            return (
              <g key={p.t} opacity={hover === null || hover === i ? 1 : 0.45} style={{ transition: 'opacity 120ms' }}>
                {segs.map((l, k) => {
                  const top = y(acc + p[l])
                  const bottom = y(acc)
                  acc += p[l]
                  const gap = k > 0 ? 2 : 0
                  const h = Math.max(0, bottom - top - gap)
                  const isTop = k === segs.length - 1
                  const r = isTop ? Math.min(4, h, barW / 2) : 0
                  return (
                    <path
                      key={l}
                      d={roundedTop(x, top, barW, h, r)}
                      fill={layerColorVar[l]}
                    />
                  )
                })}
                {p.alerts > 0 && (
                  <circle cx={x + barW / 2} cy={y(acc) - 8} r={4} fill="var(--color-sev-critical)" stroke="var(--color-surface)" strokeWidth={2} />
                )}
              </g>
            )
          })}
          {points.length > 0 &&
            [0, Math.floor(points.length / 2), points.length - 1].map((i) => (
              <text
                key={i}
                x={pad.left + (offset + i) * band + band / 2}
                y={height - 6}
                textAnchor={i === points.length - 1 ? 'end' : 'middle'}
                className="tnum fill-ink-3 text-[10px]"
              >
                {clockShort(points[i].t)}
              </text>
            ))}
          <rect
            x={pad.left}
            y={pad.top}
            width={innerW}
            height={innerH}
            fill="transparent"
            onPointerMove={(e) => {
              const box = (e.currentTarget as SVGRectElement).getBoundingClientRect()
              const i = Math.floor((e.clientX - box.left) / band) - offset
              setHover(i >= 0 && i < points.length ? i : null)
            }}
          />
        </svg>
      )}
      {hovered && hover !== null && (
        <Tooltip x={pad.left + (offset + hover) * band} y={8} width={width}>
          <p className="mb-1 font-medium text-ink">{clock(hovered.t)}</p>
          {LAYERS.map((l) => (
            <TipRow key={l} color={layerColorVar[l]} label={LAYER_LABEL[l]} value={num(hovered[l])} />
          ))}
          <div className="my-1 border-t border-line" />
          <TipRow label="Flagged events" value={num(hovered.flagged)} />
          <TipRow color="var(--color-sev-critical)" label="New alerts" value={num(hovered.alerts)} />
        </Tooltip>
      )}
      {points.length === 0 && (
        <div className="absolute inset-0 grid place-items-center text-xs text-ink-3">Waiting for telemetry…</div>
      )}
    </div>
  )
}

function roundedTop(x: number, y: number, w: number, h: number, r: number) {
  if (h <= 0) return ''
  if (r <= 0) return `M${x},${y}h${w}v${h}h${-w}Z`
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`
}

/** SHAP contributions (or z-scores) as a diverging bar chart. */
export function ExplanationBars({ items, threat }: { items: Explanation[]; threat: string }) {
  if (!items.length) return null
  const method = items[0].method
  const max = Math.max(...items.map((i) => Math.abs(i.weight)), 1e-6)
  const toward = method === 'shap' ? `Toward ${THREAT_LABEL[threat as keyof typeof THREAT_LABEL] ?? threat}` : 'Above baseline'
  const away = method === 'shap' ? 'Toward benign' : 'Below baseline'
  return (
    <div>
      <ul className="space-y-2.5">
        {items.map((it) => {
          const w = (Math.abs(it.weight) / max) * 50
          const pos = it.weight >= 0
          return (
            <li key={it.feature} className="group">
              <div className="mb-1 flex items-baseline justify-between gap-3 text-xs">
                <span className="truncate text-ink-2" title={it.feature}>{it.label}</span>
                <span className="tnum shrink-0 font-medium text-ink">{it.value}</span>
              </div>
              <div className="relative h-2">
                <div className="absolute inset-y-[-2px] left-1/2 w-px bg-axis" />
                <div
                  className={clsx('absolute inset-y-0 transition-[width] duration-500', pos ? 'left-1/2 rounded-r' : 'right-1/2 rounded-l')}
                  style={{ width: `${w}%`, background: pos ? 'var(--color-shap-pos)' : 'var(--color-shap-neg)' }}
                  title={`${method === 'shap' ? 'SHAP' : 'z'} ${it.weight > 0 ? '+' : ''}${it.weight.toFixed(2)}`}
                />
              </div>
            </li>
          )
        })}
      </ul>
      <div className="mt-3 flex justify-between text-[11px] text-ink-3">
        <span className="flex items-center gap-1.5"><span className="size-2 rounded-sm bg-shap-neg" />{away}</span>
        <span className="flex items-center gap-1.5">{toward}<span className="size-2 rounded-sm bg-shap-pos" /></span>
      </div>
    </div>
  )
}

/** Single-series horizontal bars with the value at the tip. */
export function BarList({ items, format }: { items: { key: string; label: ReactNode; value: number; color?: string }[]; format: (v: number) => string }) {
  const max = Math.max(...items.map((i) => i.value), 1e-9)
  return (
    <ul className="space-y-2">
      {items.map((it) => (
        <li key={it.key} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1">
          <span className="truncate text-xs text-ink-2">{it.label}</span>
          <span className="tnum text-xs font-medium text-ink">{format(it.value)}</span>
          <div className="col-span-2 h-1.5 rounded-full bg-subtle">
            <div
              className="h-full rounded-full transition-[width] duration-500"
              style={{ width: `${(it.value / max) * 100}%`, background: it.color ?? 'var(--color-net)' }}
            />
          </div>
        </li>
      ))}
    </ul>
  )
}

const BLUE_RAMP = ['#f4f8fe', '#cde2fb', '#9ec5f4', '#6da7ec', '#3987e5', '#256abf', '#184f95', '#0d366b']

/** Row-normalised confusion matrix. */
export function ConfusionMatrix({ labels, matrix }: { labels: string[]; matrix: number[][] }) {
  const [hover, setHover] = useState<[number, number] | null>(null)
  const rows = matrix.map((r) => {
    const total = r.reduce((a, b) => a + b, 0)
    return r.map((v) => ({ v, share: total ? v / total : 0, total }))
  })
  const name = (l: string) => THREAT_LABEL[l as keyof typeof THREAT_LABEL] ?? l
  return (
    <div className="overflow-x-auto scroll-thin">
      <table className="w-full min-w-[520px] border-separate border-spacing-[2px] text-[11px]">
        <thead>
          <tr>
            <th className="w-28 pr-2 text-left font-normal text-ink-3">actual ↓ predicted →</th>
            {labels.map((l) => (
              <th key={l} className="px-1 pb-1 font-medium text-ink-2">{name(l)}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={labels[i]}>
              <th className="pr-2 text-left font-medium text-ink-2">{name(labels[i])}</th>
              {r.map((c, j) => {
                const step = c.v === 0 ? 0 : Math.min(7, 1 + Math.floor(c.share * 7))
                const active = hover?.[0] === i && hover?.[1] === j
                return (
                  <td
                    key={j}
                    tabIndex={0}
                    onPointerEnter={() => setHover([i, j])}
                    onPointerLeave={() => setHover(null)}
                    onFocus={() => setHover([i, j])}
                    onBlur={() => setHover(null)}
                    className={clsx('h-9 rounded-[4px] text-center tnum transition-shadow', active && 'shadow-[0_0_0_2px_var(--color-ink)]')}
                    style={{ background: BLUE_RAMP[step], color: step >= 4 ? '#fff' : 'var(--color-ink)' }}
                    title={`${name(labels[i])} → ${name(labels[j])}: ${num(c.v)} of ${num(c.total)} (${(c.share * 100).toFixed(1)}%)`}
                  >
                    {c.v === 0 ? '·' : c.share >= 0.001 ? `${(c.share * 100).toFixed(c.share >= 0.1 ? 0 : 1)}%` : '<0.1%'}
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mt-2 h-4 text-xs text-ink-3">
        {hover
          ? `${name(labels[hover[0]])} predicted as ${name(labels[hover[1]])}: ${num(rows[hover[0]][hover[1]].v)} of ${num(rows[hover[0]][hover[1]].total)} events`
          : 'Each row sums to 100%. Hover a cell for counts.'}
      </p>
    </div>
  )
}

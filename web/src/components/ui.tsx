import clsx from 'clsx'
import { AlertOctagon, AlertTriangle, ChevronsUp, Info, type LucideIcon } from 'lucide-react'
import { motion } from 'motion/react'
import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { LAYER_LABEL } from '../lib/format'
import type { AlertStatus, Layer, Severity } from '../lib/types'

export const spring = { type: 'spring', stiffness: 520, damping: 40, mass: 0.8 } as const

export function Card({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <section className={clsx('min-w-0 rounded-xl border border-line bg-surface shadow-card', className)}>{children}</section>
  )
}

export function CardHeader({ title, hint, action }: { title: ReactNode; hint?: ReactNode; action?: ReactNode }) {
  return (
    <header className="flex min-h-12 items-center justify-between gap-3 border-b border-line px-4 py-2.5">
      <div className="min-w-0">
        <h2 className="truncate text-[13px] font-medium text-ink">{title}</h2>
        {hint && <p className="truncate text-xs text-ink-3">{hint}</p>}
      </div>
      {action}
    </header>
  )
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger'
  size?: 'sm' | 'md'
  icon?: LucideIcon
}

export function Button({ variant = 'secondary', size = 'md', icon: Icon, className, children, ...rest }: ButtonProps) {
  return (
    <button
      className={clsx(
        'inline-flex shrink-0 items-center justify-center gap-1.5 rounded-lg font-medium whitespace-nowrap transition-[background,box-shadow,color,transform] duration-150 select-none active:scale-[0.98] disabled:pointer-events-none disabled:opacity-50',
        size === 'sm' ? 'h-7 px-2.5 text-xs' : 'h-8 px-3 text-[13px]',
        variant === 'primary' && 'bg-ink text-white shadow-[0_1px_0_rgb(255_255_255/0.15)_inset] hover:bg-[#2a2a2a]',
        variant === 'secondary' && 'border border-line-strong bg-surface text-ink shadow-card hover:bg-subtle',
        variant === 'ghost' && 'text-ink-2 hover:bg-hover hover:text-ink',
        variant === 'danger' && 'border border-line-strong bg-surface text-sev-critical hover:bg-[#fdf1f1]',
        className,
      )}
      {...rest}
    >
      {Icon && <Icon size={size === 'sm' ? 13 : 14} strokeWidth={2} />}
      {children}
    </button>
  )
}

const SEVERITY_META: Record<Severity, { label: string; icon: LucideIcon; dot: string; text: string; bg: string }> = {
  critical: { label: 'Critical', icon: AlertOctagon, dot: 'bg-sev-critical', text: 'text-[#b42b2b]', bg: 'bg-[#fcf0f0]' },
  high: { label: 'High', icon: ChevronsUp, dot: 'bg-sev-high', text: 'text-[#b4532c]', bg: 'bg-[#fdf3ee]' },
  medium: { label: 'Medium', icon: AlertTriangle, dot: 'bg-sev-medium', text: 'text-[#8a5d00]', bg: 'bg-[#fdf7e8]' },
  low: { label: 'Low', icon: Info, dot: 'bg-sev-low', text: 'text-ink-2', bg: 'bg-subtle' },
}

export function SeverityBadge({ severity, compact }: { severity: Severity; compact?: boolean }) {
  const m = SEVERITY_META[severity]
  const Icon = m.icon
  return (
    <span className={clsx('inline-flex h-5 shrink-0 items-center gap-1 rounded-md px-1.5 text-[11px] font-medium', m.bg, m.text)}>
      <Icon size={11} strokeWidth={2.4} aria-hidden />
      {!compact && m.label}
      {compact && <span className="sr-only">{m.label}</span>}
    </span>
  )
}

export function SeverityDot({ severity, className }: { severity: Severity; className?: string }) {
  return <span className={clsx('inline-block size-2 shrink-0 rounded-full', SEVERITY_META[severity].dot, className)} />
}

export const severityLabel = (s: Severity) => SEVERITY_META[s].label

const STATUS_META: Record<AlertStatus, { label: string; cls: string }> = {
  open: { label: 'Open', cls: 'text-ink border-line-strong' },
  acknowledged: { label: 'Acknowledged', cls: 'text-accent border-[#d7d7f6] bg-accent-soft' },
  resolved: { label: 'Resolved', cls: 'text-good-ink border-[#cfe8cf] bg-[#f0f8f0]' },
  false_positive: { label: 'False positive', cls: 'text-ink-3 border-line bg-subtle' },
}

export function StatusPill({ status }: { status: AlertStatus }) {
  const m = STATUS_META[status]
  return (
    <span className={clsx('inline-flex h-5 items-center rounded-full border px-2 text-[11px] font-medium whitespace-nowrap', m.cls)}>
      {m.label}
    </span>
  )
}

export const statusLabel = (s: AlertStatus) => STATUS_META[s].label

const LAYER_COLOR: Record<Layer, string> = { network: 'bg-net', endpoint: 'bg-end', application: 'bg-app' }
export const layerColorVar: Record<Layer, string> = {
  network: 'var(--color-net)',
  endpoint: 'var(--color-end)',
  application: 'var(--color-app)',
}

export function LayerTag({ layer }: { layer: Layer }) {
  return (
    <span className="inline-flex h-5 items-center gap-1.5 rounded-md border border-line px-1.5 text-[11px] text-ink-2">
      <span className={clsx('size-1.5 rounded-full', LAYER_COLOR[layer])} />
      {LAYER_LABEL[layer]}
    </span>
  )
}

export function ConfidenceMeter({ value, className }: { value: number; className?: string }) {
  return (
    <span className={clsx('inline-flex items-center gap-2', className)}>
      <span className="relative h-1 w-12 overflow-hidden rounded-full bg-subtle">
        <motion.span
          className="absolute inset-y-0 left-0 rounded-full bg-ink"
          initial={false}
          animate={{ width: `${Math.round(value * 100)}%` }}
          transition={spring}
        />
      </span>
      <span className="tnum text-xs text-ink-2">{Math.round(value * 100)}%</span>
    </span>
  )
}

export function Kbd({ children }: { children: ReactNode }) {
  return (
    <kbd className="inline-flex h-5 min-w-5 items-center justify-center rounded border border-line-strong bg-surface px-1 font-sans text-[11px] text-ink-3">
      {children}
    </kbd>
  )
}

export function Segmented<T extends string | number>({
  value, options, onChange, label,
}: {
  value: T
  options: { value: T; label: string }[]
  onChange: (v: T) => void
  label: string
}) {
  return (
    <div role="radiogroup" aria-label={label} className="relative inline-flex h-8 items-center rounded-lg bg-subtle p-0.5">
      {options.map((o) => {
        const active = o.value === value
        return (
          <button
            key={String(o.value)}
            role="radio"
            aria-checked={active}
            onClick={() => onChange(o.value)}
            className={clsx(
              'relative h-7 rounded-md px-2.5 text-xs font-medium transition-colors',
              active ? 'text-ink' : 'text-ink-3 hover:text-ink-2',
            )}
          >
            {active && (
              <motion.span
                layoutId={`seg-${label}`}
                className="absolute inset-0 rounded-md bg-surface shadow-[0_1px_2px_rgb(0_0_0/0.08),0_0_0_1px_rgb(0_0_0/0.04)]"
                transition={spring}
              />
            )}
            <span className="relative">{o.label}</span>
          </button>
        )
      })}
    </div>
  )
}

export function Empty({ icon: Icon, title, body, action }: { icon: LucideIcon; title: string; body?: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-14 text-center">
      <div className="mb-3 grid size-10 place-items-center rounded-xl border border-line bg-subtle text-ink-3">
        <Icon size={18} />
      </div>
      <p className="text-[13px] font-medium text-ink">{title}</p>
      {body && <p className="mt-1 max-w-sm text-xs text-ink-3">{body}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={clsx('animate-pulse rounded-md bg-subtle', className)} />
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={clsx('font-mono text-[12px] tracking-tight', className)}>{children}</span>
}

export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3 pb-5">
      <div>
        <h1 className="text-[20px] font-semibold tracking-[-0.015em] text-ink">{title}</h1>
        {description && <p className="mt-1 max-w-2xl text-[13px] text-ink-3">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

export function Stat({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: 'critical' }) {
  return (
    <div className="min-w-0 px-4 py-3.5">
      <p className="truncate text-xs text-ink-3">{label}</p>
      <p className={clsx('mt-1 text-[22px] leading-7 font-semibold tracking-[-0.02em]', tone === 'critical' ? 'text-[#b42b2b]' : 'text-ink')}>
        {value}
      </p>
      {sub && <p className="mt-0.5 truncate text-xs text-ink-3">{sub}</p>}
    </div>
  )
}

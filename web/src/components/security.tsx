import clsx from 'clsx'
import { Check, ExternalLink } from 'lucide-react'
import { motion } from 'motion/react'
import { useState } from 'react'
import type { Playbook } from '../lib/types'
import { spring } from './ui'

export const KILL_CHAIN = [
  { tactic: 'Discovery', short: 'Discover' },
  { tactic: 'Credential Access', short: 'Credentials' },
  { tactic: 'Lateral Movement', short: 'Lateral' },
  { tactic: 'Command and Control', short: 'C2' },
  { tactic: 'Exfiltration', short: 'Exfil' },
]

/** Five ATT&CK tactics; reached ones are filled. */
export function KillChain({ reached, current }: { reached: string[]; current?: string }) {
  const hit = new Set(reached)
  return (
    <ol className="grid grid-cols-5 gap-1" aria-label="Kill chain progress">
      {KILL_CHAIN.map((s, i) => {
        const on = hit.has(s.tactic)
        const isCurrent = current === s.tactic
        return (
          <li key={s.tactic} className="min-w-0">
            <motion.div
              className={clsx('h-1.5 rounded-full', on ? (isCurrent ? 'bg-sev-critical' : 'bg-ink') : 'bg-subtle')}
              initial={{ scaleX: 0.3, opacity: 0 }}
              animate={{ scaleX: 1, opacity: 1 }}
              transition={{ ...spring, delay: i * 0.04 }}
              style={{ transformOrigin: 'left' }}
            />
            <p className={clsx('mt-1.5 truncate text-[11px]', on ? 'font-medium text-ink' : 'text-ink-3')} title={s.tactic}>
              <span className="hidden sm:inline">{s.tactic}</span>
              <span className="sm:hidden">{s.short}</span>
              <span className="sr-only">{on ? ' (observed)' : ' (not observed)'}</span>
            </p>
          </li>
        )
      })}
    </ol>
  )
}

export function MitreTag({ id, name }: { id: string; name?: string }) {
  const path = id.replace('.', '/')
  return (
    <a
      href={`https://attack.mitre.org/techniques/${path}/`}
      target="_blank"
      rel="noreferrer"
      className="group inline-flex h-6 items-center gap-1.5 rounded-md border border-line bg-surface px-2 text-[11px] text-ink-2 transition-colors hover:border-line-strong hover:text-ink"
    >
      <span className="font-mono font-medium text-ink">{id}</span>
      {name && <span className="max-w-[180px] truncate">{name}</span>}
      <ExternalLink size={10} className="text-ink-3 opacity-0 transition-opacity group-hover:opacity-100" />
    </a>
  )
}

const PHASES: { key: keyof Playbook; label: string }[] = [
  { key: 'contain', label: 'Contain' },
  { key: 'investigate', label: 'Investigate' },
  { key: 'remediate', label: 'Remediate' },
]

export function PlaybookView({ playbook, id }: { playbook: Playbook; id: string }) {
  const [phase, setPhase] = useState<keyof Playbook>('contain')
  const [done, setDone] = useState<Set<string>>(new Set())
  const toggle = (step: string) =>
    setDone((d) => {
      const next = new Set(d)
      if (next.has(step)) next.delete(step)
      else next.add(step)
      return next
    })
  return (
    <div>
      <div className="mb-3 flex gap-1 border-b border-line" role="tablist">
        {PHASES.map((p) => (
          <button
            key={p.key}
            role="tab"
            aria-selected={phase === p.key}
            onClick={() => setPhase(p.key)}
            className={clsx('relative px-2.5 pb-2 text-xs font-medium transition-colors', phase === p.key ? 'text-ink' : 'text-ink-3 hover:text-ink-2')}
          >
            {p.label}
            <span className="tnum ml-1 text-ink-3">{playbook[p.key].length}</span>
            {phase === p.key && (
              <motion.span layoutId={`pb-${id}`} className="absolute inset-x-1 -bottom-px h-0.5 rounded-full bg-ink" transition={spring} />
            )}
          </button>
        ))}
      </div>
      <ul className="space-y-1">
        {playbook[phase].map((step) => {
          const checked = done.has(step)
          return (
            <li key={step}>
              <button
                onClick={() => toggle(step)}
                className="flex w-full items-start gap-2.5 rounded-lg px-2 py-1.5 text-left text-[13px] transition-colors hover:bg-subtle"
                aria-pressed={checked}
              >
                <span
                  className={clsx(
                    'mt-0.5 grid size-4 shrink-0 place-items-center rounded-[5px] border transition-colors',
                    checked ? 'border-ink bg-ink text-white' : 'border-line-strong bg-surface',
                  )}
                >
                  {checked && <Check size={11} strokeWidth={3} />}
                </span>
                <span className={clsx('transition-colors', checked ? 'text-ink-3 line-through' : 'text-ink-2')}>{step}</span>
              </button>
            </li>
          )
        })}
      </ul>
    </div>
  )
}

export function RiskRing({ value, size = 44 }: { value: number; size?: number }) {
  const r = size / 2 - 3
  const c = 2 * Math.PI * r
  const color = value >= 80 ? 'var(--color-sev-critical)' : value >= 60 ? 'var(--color-sev-high)' : 'var(--color-sev-medium)'
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }} aria-label={`Risk ${value} of 100`}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--color-subtle)" strokeWidth={3} />
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={3}
          strokeLinecap="round"
          strokeDasharray={c}
          initial={{ strokeDashoffset: c }}
          animate={{ strokeDashoffset: c * (1 - value / 100) }}
          transition={{ duration: 0.8, ease: [0.2, 0.8, 0.2, 1] }}
        />
      </svg>
      <span className="tnum absolute inset-0 grid place-items-center text-[13px] font-semibold">{value}</span>
    </div>
  )
}

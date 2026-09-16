import clsx from 'clsx'
import { ShieldCheck, Users, X } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { KillChain, MitreTag, PlaybookView, RiskRing } from '../components/security'
import { Drawer } from '../components/shell'
import { Button, Card, Empty, LayerTag, Mono, PageHeader, SeverityBadge, SeverityDot, Skeleton, spring, StatusPill } from '../components/ui'
import { api } from '../lib/api'
import { ago, clock, duration, THREAT_LABEL } from '../lib/format'
import { navigate } from '../lib/router'
import { useStore } from '../lib/store'
import type { Incident } from '../lib/types'

export default function Incidents({ selected }: { selected?: string }) {
  const incidentsMap = useStore((s) => s.incidents)
  const now = useStore((s) => s.overview?.now ?? 0)
  const incidents = useMemo(() => Object.values(incidentsMap).sort((a, b) => b.last_seen - a.last_seen), [incidentsMap])
  const close = useCallback(() => navigate('/incidents'), [])

  return (
    <div>
      <PageHeader
        title="Incidents"
        description="Alerts that share a host, a compromised account or an external endpoint within three hours are merged into one incident, ordered along the kill chain."
      />
      {incidents.length === 0 ? (
        <Card>
          <Empty
            icon={ShieldCheck}
            title="No incidents"
            body="Single alerts stay alerts. An incident needs corroboration: several techniques, several hosts, or several telemetry layers."
            action={<Button variant="primary" onClick={() => navigate('/simulate')}>Run the kill-chain scenario</Button>}
          />
        </Card>
      ) : (
        <div className="grid gap-3 lg:grid-cols-2">
          <AnimatePresence initial={false}>
            {incidents.map((inc) => (
              <motion.a
                layout
                key={inc.id}
                href={`#/incidents/${inc.id}`}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.98 }}
                transition={spring}
                className={clsx(
                  'group block rounded-xl border bg-surface p-4 shadow-card transition-[border-color,box-shadow] hover:border-line-strong hover:shadow-pop',
                  selected === inc.id ? 'border-ink/40' : 'border-line',
                )}
              >
                <div className="flex items-start gap-4">
                  <RiskRing value={inc.risk} size={48} />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={inc.severity} />
                      <span className="font-mono text-[11px] text-ink-3">{inc.id}</span>
                      <span className="text-[11px] text-ink-3">· updated {ago(inc.last_seen, now)}</span>
                    </div>
                    <p className="mt-1.5 text-[14px] leading-snug font-medium">{inc.title}</p>
                  </div>
                </div>
                <div className="mt-4">
                  <KillChain reached={inc.tactics} />
                </div>
                <div className="mt-4 flex flex-wrap items-center gap-1.5 text-[11px] text-ink-3">
                  {inc.layers.map((l) => <LayerTag key={l} layer={l} />)}
                  <span>· {inc.alert_count} alerts · {inc.entities.length} hosts · spans {duration(inc.last_seen - inc.first_seen)}</span>
                </div>
              </motion.a>
            ))}
          </AnimatePresence>
        </div>
      )}
      <Drawer open={!!selected} onClose={close} width={720}>
        {selected && <IncidentPanel id={selected} onClose={close} />}
      </Drawer>
    </div>
  )
}

function IncidentPanel({ id, onClose }: { id: string; onClose: () => void }) {
  const live = useStore((s) => s.incidents[id])
  const [detail, setDetail] = useState<Incident | null>(null)
  const [missing, setMissing] = useState(false)
  const stamp = live ? `${live.last_seen}-${live.alert_count}` : ''

  useEffect(() => {
    let active = true
    api.incident(id).then((d) => active && setDetail(d)).catch(() => active && setMissing(true))
    return () => {
      active = false
    }
  }, [id, stamp])

  if (missing) return <Empty icon={ShieldCheck} title="Incident not found" body="It may have been merged or cleared." action={<Button onClick={onClose}>Close</Button>} />
  if (!detail) {
    return (
      <div className="space-y-3 p-6">
        <Skeleton className="h-6 w-40" />
        <Skeleton className="h-8 w-3/4" />
        <Skeleton className="h-24" />
        <Skeleton className="h-64" />
      </div>
    )
  }
  const inc = detail
  return (
    <>
      <header className="border-b border-line px-6 pt-5 pb-5">
        <div className="flex items-start gap-4">
          <RiskRing value={inc.risk} size={56} />
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={inc.severity} />
              <span className="font-mono text-[11px] text-ink-3">{inc.id}</span>
              <span className="text-[11px] text-ink-3">· risk {inc.risk}/100 · confidence {Math.round(inc.confidence * 100)}%</span>
            </div>
            <h2 className="mt-2 text-[17px] leading-snug font-semibold tracking-[-0.01em]">{inc.title}</h2>
            <p className="mt-1 text-xs text-ink-3">
              {clock(inc.first_seen)} → {clock(inc.last_seen)} UTC · {inc.alert_count} alerts across {inc.layers.length} layers
            </p>
          </div>
          <button onClick={onClose} className="grid size-7 place-items-center rounded-md text-ink-3 hover:bg-hover hover:text-ink" aria-label="Close">
            <X size={15} />
          </button>
        </div>
        <div className="mt-5">
          <KillChain reached={inc.tactics} />
        </div>
      </header>

      <div className="scroll-thin flex-1 overflow-y-auto">
        <section className="border-b border-line px-6 py-5">
          <h3 className="mb-4 text-xs font-medium text-ink-3">Attack story</h3>
          <ol className="relative space-y-4 before:absolute before:top-1.5 before:bottom-1.5 before:left-[5px] before:w-px before:bg-line">
            {inc.story.map((s, i) => {
              const alert = inc.alerts?.find((a) => a.id === s.alert_id)
              return (
                <motion.li
                  key={s.alert_id}
                  className="relative pl-6"
                  initial={{ opacity: 0, x: -4 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ ...spring, delay: Math.min(i, 10) * 0.03 }}
                >
                  <span className="absolute top-1 left-0 grid size-[11px] place-items-center rounded-full border-2 border-surface bg-surface">
                    {alert ? <SeverityDot severity={alert.severity} /> : <span className="size-2 rounded-full bg-ink-3" />}
                  </span>
                  <div className="flex flex-wrap items-center gap-x-2 text-[11px] text-ink-3">
                    <span className="tnum">{clock(s.ts)}</span>
                    <span className="font-medium text-ink-2">{THREAT_LABEL[s.threat]}</span>
                    <a href={`#/alerts/${s.alert_id}`} className="font-mono hover:text-ink hover:underline">{s.alert_id}</a>
                    {alert && <StatusPill status={alert.status} />}
                  </div>
                  <p className="mt-0.5 text-[13px] leading-relaxed text-ink">{s.text}</p>
                </motion.li>
              )
            })}
          </ol>
        </section>

        <div className="grid border-b border-line md:grid-cols-2 md:divide-x md:divide-line">
          <section className="px-6 py-5">
            <h3 className="mb-3 text-xs font-medium text-ink-3">Hosts involved</h3>
            <ul className="space-y-1.5">
              {inc.entities.map((e) => (
                <li key={e.ip} className="flex items-center justify-between gap-2 text-[13px]">
                  <span className="truncate">{e.hostname ?? 'unmanaged'}</span>
                  <span className="shrink-0 text-[11px] text-ink-3"><Mono>{e.ip}</Mono> · {e.role}</span>
                </li>
              ))}
            </ul>
            {inc.users.length > 0 && (
              <>
                <h3 className="mt-5 mb-2 flex items-center gap-1.5 text-xs font-medium text-ink-3"><Users size={12} />Accounts used</h3>
                <p className="text-[13px] text-[#b42b2b]">{inc.users.join(', ')}</p>
              </>
            )}
          </section>
          <section className="px-6 py-5 max-md:border-t max-md:border-line">
            <h3 className="mb-3 text-xs font-medium text-ink-3">ATT&CK techniques</h3>
            <div className="flex flex-wrap gap-1.5">
              {inc.mitre.map((m) => {
                const [tid, ...name] = m.split(' ')
                return <MitreTag key={m} id={tid} name={name.join(' ')} />
              })}
            </div>
          </section>
        </div>

        <section className="px-6 py-5">
          <h3 className="mb-3 text-xs font-medium text-ink-3">Coordinated response</h3>
          <PlaybookView playbook={inc.playbook} id={inc.id} />
        </section>
      </div>
    </>
  )
}

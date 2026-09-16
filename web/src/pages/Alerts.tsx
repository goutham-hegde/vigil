import clsx from 'clsx'
import { ArrowRight, BellOff, Check, CheckCheck, CircleSlash, Eye, Search, ShieldAlert, X } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { BarList, ExplanationBars } from '../components/charts'
import { KillChain, MitreTag, PlaybookView } from '../components/security'
import { Drawer } from '../components/shell'
import {
  Button, Card, ConfidenceMeter, Empty, Kbd, LayerTag, Mono, PageHeader, Segmented, SeverityBadge, Skeleton, spring, StatusPill,
} from '../components/ui'
import { api } from '../lib/api'
import { ago, bytes, clock, num, SEVERITY_ORDER, SEVERITY_RANK, THREAT_LABEL } from '../lib/format'
import { navigate } from '../lib/router'
import { sortedAlerts, useStore } from '../lib/store'
import type { AlertDetail, AlertStatus, Severity } from '../lib/types'

type StatusFilter = 'active' | 'closed' | 'all'
const ACTIVE: AlertStatus[] = ['open', 'acknowledged']

export default function Alerts({ selected }: { selected?: string }) {
  const alertsMap = useStore((s) => s.alerts)
  const now = useStore((s) => s.overview?.now ?? 0)
  const query = useStore((s) => s.alertQuery)
  const setQuery = useStore((s) => s.setAlertQuery)
  const [status, setStatus] = useState<StatusFilter>('active')
  const [severities, setSeverities] = useState<Set<Severity>>(new Set())
  const [sort, setSort] = useState<'recent' | 'severity'>('recent')
  const [cursor, setCursor] = useState(0)
  const searchRef = useRef<HTMLInputElement>(null)

  const alerts = useMemo(() => {
    const q = query.trim().toLowerCase()
    let list = sortedAlerts(alertsMap)
    if (status === 'active') list = list.filter((a) => ACTIVE.includes(a.status))
    if (status === 'closed') list = list.filter((a) => !ACTIVE.includes(a.status))
    if (severities.size) list = list.filter((a) => severities.has(a.severity))
    if (q) {
      list = list.filter((a) =>
        `${a.id} ${a.entity} ${a.hostname ?? ''} ${a.title} ${a.summary} ${a.threat}`.toLowerCase().includes(q),
      )
    }
    if (sort === 'severity') {
      list = [...list].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.confidence - a.confidence)
    }
    return list
  }, [alertsMap, status, severities, query, sort])

  useEffect(() => setCursor((c) => Math.min(c, Math.max(0, alerts.length - 1))), [alerts.length])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement
      if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || useStore.getState().paletteOpen) return
      if (e.key === '/') {
        e.preventDefault()
        searchRef.current?.focus()
      } else if (!selected && (e.key === 'j' || e.key === 'ArrowDown')) {
        e.preventDefault()
        setCursor((c) => Math.min(alerts.length - 1, c + 1))
      } else if (!selected && (e.key === 'k' || e.key === 'ArrowUp')) {
        e.preventDefault()
        setCursor((c) => Math.max(0, c - 1))
      } else if (!selected && e.key === 'Enter' && alerts[cursor]) {
        navigate(`/alerts/${alerts[cursor].id}`)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [alerts, cursor, selected])

  const toggleSeverity = (s: Severity) =>
    setSeverities((prev) => {
      const next = new Set(prev)
      if (next.has(s)) next.delete(s)
      else next.add(s)
      return next
    })

  const close = useCallback(() => navigate('/alerts'), [])

  return (
    <div>
      <PageHeader
        title="Alerts"
        description="One alert per source and technique. New detections from the same source fold into the open alert instead of creating noise."
      />

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative w-full sm:w-72">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-ink-3" />
          <input
            ref={searchRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by host, IP, technique…"
            className="h-8 w-full rounded-lg border border-line-strong bg-surface pr-8 pl-8 text-[13px] shadow-card outline-none transition-shadow placeholder:text-ink-3 focus:border-accent focus:shadow-[0_0_0_3px_var(--color-accent-soft)]"
          />
          {query ? (
            <button onClick={() => setQuery('')} className="absolute top-1/2 right-2 -translate-y-1/2 text-ink-3 hover:text-ink" aria-label="Clear filter">
              <X size={13} />
            </button>
          ) : (
            <span className="absolute top-1/2 right-2 -translate-y-1/2"><Kbd>/</Kbd></span>
          )}
        </div>
        <Segmented
          label="Status"
          value={status}
          onChange={setStatus}
          options={[
            { value: 'active', label: 'Active' },
            { value: 'closed', label: 'Closed' },
            { value: 'all', label: 'All' },
          ]}
        />
        <div className="flex items-center gap-1">
          {SEVERITY_ORDER.map((s) => (
            <button
              key={s}
              onClick={() => toggleSeverity(s)}
              aria-pressed={severities.has(s)}
              className={clsx(
                'rounded-lg border p-0.5 transition-all',
                severities.has(s) ? 'border-ink/40 bg-surface shadow-card' : 'border-transparent opacity-70 hover:opacity-100',
              )}
            >
              <SeverityBadge severity={s} />
            </button>
          ))}
        </div>
        <div className="flex-1" />
        <Segmented
          label="Sort"
          value={sort}
          onChange={setSort}
          options={[
            { value: 'recent', label: 'Recent' },
            { value: 'severity', label: 'Severity' },
          ]}
        />
      </div>

      <Card className="overflow-hidden">
        <div className="hidden grid-cols-[92px_minmax(0,1fr)_170px_120px_90px_110px] gap-4 border-b border-line bg-subtle/50 px-4 py-2 text-[11px] font-medium text-ink-3 md:grid">
          <span>Severity</span>
          <span>Alert</span>
          <span>Source</span>
          <span>Confidence</span>
          <span className="text-right">Events</span>
          <span className="text-right">Status</span>
        </div>
        {alerts.length === 0 ? (
          <Empty
            icon={BellOff}
            title={Object.keys(alertsMap).length ? 'Nothing matches these filters' : 'No alerts yet'}
            body={Object.keys(alertsMap).length ? 'Try clearing the search or severity filters.' : 'Launch a scenario from Simulation to generate attack traffic.'}
            action={!Object.keys(alertsMap).length && <Button variant="primary" onClick={() => navigate('/simulate')}>Open simulation</Button>}
          />
        ) : (
          <ul role="list">
            <AnimatePresence initial={false}>
              {alerts.slice(0, 250).map((a, i) => (
                <motion.li
                  key={a.id}
                  layout="position"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.18 }}
                  className="border-b border-line last:border-b-0"
                >
                  <a
                    href={`#/alerts/${a.id}`}
                    onMouseEnter={() => setCursor(i)}
                    className={clsx(
                      'relative grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 px-4 py-3 transition-colors md:grid-cols-[92px_minmax(0,1fr)_170px_120px_90px_110px] md:items-center md:gap-4',
                      (i === cursor || a.id === selected) && 'bg-subtle/70',
                      !ACTIVE.includes(a.status) && 'opacity-60',
                    )}
                  >
                    {(i === cursor || a.id === selected) && <span className="absolute inset-y-0 left-0 w-0.5 bg-ink" />}
                    <span><SeverityBadge severity={a.severity} /></span>
                    <span className="min-w-0">
                      <span className="flex items-center gap-2">
                        <span className="truncate text-[13px] font-medium">{a.title}</span>
                        {a.detector === 'anomaly' && <span className="rounded border border-line px-1 text-[10px] text-ink-3">unsupervised</span>}
                        {a.incident_id && <span className="flex shrink-0 items-center gap-1 text-[11px] text-ink-3"><ShieldAlert size={11} />{a.incident_id}</span>}
                      </span>
                      <span className="mt-0.5 block truncate text-xs text-ink-3">{a.summary}</span>
                    </span>
                    <span className="col-start-2 min-w-0 md:col-start-auto">
                      <span className="block truncate text-[13px]">{a.hostname ?? a.entity}</span>
                      <span className="block truncate text-[11px] text-ink-3"><Mono>{a.entity}</Mono> · {ago(a.last_seen, now)}</span>
                    </span>
                    <ConfidenceMeter value={a.confidence} className="col-start-2 md:col-start-auto" />
                    <span className="tnum hidden text-right text-[13px] text-ink-2 md:block">{num(a.event_count)}</span>
                    <span className="col-start-2 md:col-start-auto md:text-right"><StatusPill status={a.status} /></span>
                  </a>
                </motion.li>
              ))}
            </AnimatePresence>
          </ul>
        )}
      </Card>
      <p className="mt-2 hidden text-xs text-ink-3 md:block">
        <Kbd>j</Kbd> <Kbd>k</Kbd> to move, <Kbd>↵</Kbd> to open, <Kbd>/</Kbd> to filter, <Kbd>esc</Kbd> to close.
      </p>

      <Drawer open={!!selected} onClose={close} width={600}>
        {selected && <AlertPanel id={selected} onClose={close} />}
      </Drawer>
    </div>
  )
}

function Section({ title, children, aside }: { title: string; children: React.ReactNode; aside?: React.ReactNode }) {
  return (
    <section className="border-b border-line px-5 py-4 last:border-b-0">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-xs font-medium text-ink-3">{title}</h3>
        {aside}
      </div>
      {children}
    </section>
  )
}

export function AlertPanel({ id, onClose }: { id: string; onClose: () => void }) {
  const summary = useStore((s) => s.alerts[id])
  const upsertAlert = useStore((s) => s.upsertAlert)
  const toast = useStore((s) => s.toast)
  const [detail, setDetail] = useState<AlertDetail | null>(null)
  const [missing, setMissing] = useState(false)
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const revision = summary?.revision

  useEffect(() => {
    let live = true
    const t = setTimeout(() => {
      api.alert(id).then((d) => live && setDetail(d)).catch(() => live && setMissing(true))
    }, detail ? 400 : 0)
    return () => {
      live = false
      clearTimeout(t)
    }
    // `revision` changes whenever the alert absorbs new events.
  }, [id, revision])

  const setStatus = async (status: AlertStatus) => {
    setBusy(true)
    try {
      const d = await api.setAlertStatus(id, status, note || undefined)
      setDetail(d)
      upsertAlert(d)
      setNote('')
      toast({
        tone: 'success',
        title: status === 'false_positive' ? 'Marked as false positive' : `Alert ${status.replace('_', ' ')}`,
        body: status === 'false_positive' ? 'Saved to the feedback log for the next training run.' : undefined,
      })
    } finally {
      setBusy(false)
    }
  }

  if (missing) {
    return <Empty icon={BellOff} title="Alert not found" body="It may have been cleared by an engine reset." action={<Button onClick={onClose}>Close</Button>} />
  }
  if (!detail) {
    return (
      <div className="space-y-3 p-5">
        <Skeleton className="h-5 w-24" />
        <Skeleton className="h-7 w-3/4" />
        <Skeleton className="h-40" />
        <Skeleton className="h-40" />
      </div>
    )
  }

  const d = detail
  const probs = Object.entries(d.class_probs).filter(([, p]) => p >= 0.005).sort((a, b) => b[1] - a[1])
  return (
    <>
      <header className="border-b border-line px-5 pt-4 pb-4">
        <div className="flex items-center gap-2">
          <SeverityBadge severity={d.severity} />
          <StatusPill status={d.status} />
          <span className="font-mono text-[11px] text-ink-3">{d.id}</span>
          <div className="flex-1" />
          <button onClick={onClose} className="grid size-7 place-items-center rounded-md text-ink-3 hover:bg-hover hover:text-ink" aria-label="Close">
            <X size={15} />
          </button>
        </div>
        <h2 className="mt-2.5 text-[17px] font-semibold tracking-[-0.01em]">{d.title}</h2>
        <p className="mt-1 text-[13px] leading-relaxed text-ink-2">{d.summary}</p>
        <div className="mt-3 flex flex-wrap items-center gap-1.5">
          {d.layers.map((l) => <LayerTag key={l} layer={l} />)}
          <span className="text-[11px] text-ink-3">· {d.detector === 'supervised' ? 'Classifier' : 'Anomaly detector'} · {num(d.event_count)} events · {clock(d.first_seen)}–{clock(d.last_seen)} UTC</span>
        </div>
      </header>

      <div className="scroll-thin flex-1 overflow-y-auto">
        {d.incident_id && (
          <a href={`#/incidents/${d.incident_id}`} className="group mx-5 mt-4 flex items-center gap-2 rounded-lg border border-[#f3d4d4] bg-[#fdf5f5] px-3 py-2 text-[13px] text-[#8f2424]">
            <ShieldAlert size={14} />
            <span className="flex-1">Part of incident <span className="font-mono">{d.incident_id}</span></span>
            <ArrowRight size={14} className="transition-transform group-hover:translate-x-0.5" />
          </a>
        )}

        <Section title="Why this was flagged" aside={<ConfidenceMeter value={d.confidence} />}>
          <ExplanationBars items={d.explanation} threat={d.threat} />
          <p className="mt-3 text-[11px] leading-relaxed text-ink-3">
            {d.explanation[0]?.method === 'shap'
              ? 'TreeSHAP contributions in log-odds for the predicted class, computed on the event that raised or last strengthened this alert.'
              : 'Distance from the benign baseline in standard deviations. Isolation forests have no native attribution.'}
          </p>
        </Section>

        {probs.length > 1 && (
          <Section title="Class probabilities">
            <BarList
              items={probs.map(([k, p]) => ({ key: k, label: THREAT_LABEL[k as keyof typeof THREAT_LABEL] ?? k, value: p, color: k === 'benign' ? 'var(--color-sev-low)' : 'var(--color-ink-2)' }))}
              format={(v) => `${(v * 100).toFixed(1)}%`}
            />
          </Section>
        )}

        <Section title="ATT&CK mapping">
          {d.stage > 0 && <div className="mb-3"><KillChain reached={[d.tactic]} current={d.tactic} /></div>}
          <div className="flex flex-wrap gap-1.5">
            {d.mitre.length ? d.mitre.map((m) => <MitreTag key={m.id} id={m.id} name={m.name} />) : <span className="text-xs text-ink-3">No technique mapped to anomalies.</span>}
          </div>
        </Section>

        <Section title="Entities">
          <dl className="grid grid-cols-[110px_minmax(0,1fr)] gap-x-3 gap-y-2 text-[13px]">
            <dt className="text-ink-3">Source</dt>
            <dd>{d.hostname ?? 'unmanaged'} <Mono className="text-ink-3">{d.entity}</Mono> <span className="text-xs text-ink-3">· {d.role}</span></dd>
            <dt className="text-ink-3">Targets</dt>
            <dd className="flex flex-wrap gap-1">
              {d.targets.length ? d.targets.map((t) => (
                <span key={t.ip} className="rounded border border-line px-1.5 font-mono text-[11px] text-ink-2">{t.ip}<span className="text-ink-3"> ×{t.count}</span></span>
              )) : '—'}
              {d.target_count > d.targets.length && <span className="text-xs text-ink-3">+{d.target_count - d.targets.length} more</span>}
            </dd>
            {d.users.length > 0 && (<><dt className="text-ink-3">Accounts</dt><dd className="truncate">{d.users.slice(0, 6).join(', ')}{d.users.length > 6 && '…'}</dd></>)}
            {d.compromised_users.length > 0 && (<><dt className="text-ink-3">Used successfully</dt><dd className="font-medium text-[#b42b2b]">{d.compromised_users.join(', ')}</dd></>)}
            {d.ports.length > 0 && (<><dt className="text-ink-3">Ports</dt><dd className="font-mono text-xs">{d.ports.join(', ')}</dd></>)}
            {d.auth_failures > 0 && (<><dt className="text-ink-3">Failed logins</dt><dd className="tnum">{num(d.auth_failures)}</dd></>)}
            {d.bytes_out > 0 && (<><dt className="text-ink-3">Sent externally</dt><dd className="tnum">{bytes(d.bytes_out)}</dd></>)}
          </dl>
        </Section>

        <Section title="Response playbook">
          <PlaybookView playbook={d.playbook} id={d.id} />
        </Section>

        <Section title="Evidence" aside={<span className="text-[11px] text-ink-3">Last {d.evidence.length} contributing events</span>}>
          <div className="scroll-thin max-h-56 overflow-auto rounded-lg border border-line bg-subtle/60">
            <pre className="p-3 font-mono text-[11px] leading-relaxed text-ink-2">
              {d.evidence.slice().reverse().map((e) => JSON.stringify({ ...e, ts: clock(e.ts) })).join('\n')}
            </pre>
          </div>
        </Section>

        <Section title="Simulation ground truth">
          <p className={clsx('flex items-center gap-2 text-[13px]', d.ground_truth === 'malicious' ? 'text-ink' : 'text-[#8a5d00]')}>
            {d.ground_truth === 'malicious' ? <Check size={14} className="text-good-ink" /> : <CircleSlash size={14} />}
            {d.ground_truth === 'malicious'
              ? 'Most contributing events came from an injected attack. True positive.'
              : 'Most contributing events were benign. This is a false positive; mark it so it feeds the next training run.'}
          </p>
        </Section>

        {d.notes.length > 0 && (
          <Section title="Activity">
            <ul className="space-y-2">
              {d.notes.map((n, i) => (
                <li key={i} className="text-[13px]"><StatusPill status={n.status} /> <span className="text-ink-2">{n.text}</span> <span className="text-[11px] text-ink-3">{clock(n.ts)}</span></li>
              ))}
            </ul>
          </Section>
        )}
      </div>

      <footer className="border-t border-line bg-canvas px-5 py-3">
        <input
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="Add a note (optional)"
          className="mb-2.5 h-8 w-full rounded-lg border border-line-strong bg-surface px-2.5 text-[13px] outline-none placeholder:text-ink-3 focus:border-accent"
        />
        <motion.div layout transition={spring} className="flex flex-wrap gap-2">
          {d.status === 'open' && <Button icon={Eye} disabled={busy} onClick={() => setStatus('acknowledged')}>Acknowledge</Button>}
          {ACTIVE.includes(d.status) ? (
            <>
              <Button variant="primary" icon={CheckCheck} disabled={busy} onClick={() => setStatus('resolved')}>Resolve</Button>
              <Button variant="danger" icon={CircleSlash} disabled={busy} onClick={() => setStatus('false_positive')}>False positive</Button>
            </>
          ) : (
            <Button disabled={busy} onClick={() => setStatus('open')}>Reopen</Button>
          )}
        </motion.div>
      </footer>
    </>
  )
}

import clsx from 'clsx'
import { ArrowUpRight, BellRing, Radio, ShieldCheck } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useMemo } from 'react'
import { ActivityChart, BarList, Legend } from '../components/charts'
import { KillChain, RiskRing } from '../components/security'
import {
  Card, CardHeader, Empty, layerColorVar, Mono, PageHeader, SeverityBadge, SeverityDot, severityLabel, Skeleton, Stat, spring,
} from '../components/ui'
import { ago, bytes, clock, compact, duration, LAYER_LABEL, LAYERS, num, SEVERITY_ORDER, THREAT_LABEL } from '../lib/format'
import { sortedAlerts, useStore } from '../lib/store'
import type { Telemetry } from '../lib/types'

const SEV_COLOR = {
  critical: 'var(--color-sev-critical)',
  high: 'var(--color-sev-high)',
  medium: 'var(--color-sev-medium)',
  low: 'var(--color-sev-low)',
} as const

export default function Overview() {
  const overview = useStore((s) => s.overview)
  const alertsMap = useStore((s) => s.alerts)
  const incidentsMap = useStore((s) => s.incidents)
  const setAlertQuery = useStore((s) => s.setAlertQuery)
  const alerts = useMemo(() => sortedAlerts(alertsMap).filter((a) => a.status !== 'resolved' && a.status !== 'false_positive'), [alertsMap])
  const incidents = useMemo(
    () => Object.values(incidentsMap).sort((a, b) => b.risk - a.risk || b.last_seen - a.last_seen),
    [incidentsMap],
  )

  if (!overview) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-24" />
        <Skeleton className="h-72" />
      </div>
    )
  }

  const critical = overview.open_by_severity.critical ?? 0
  const runsDone = overview.median_time_to_detect !== null
  return (
    <div>
      <PageHeader
        title="Overview"
        description="Live telemetry from network, endpoint and application sensors, scored as it arrives by a gradient-boosted classifier and an anomaly detector."
      />

      <Card className="mb-4 grid grid-cols-2 divide-line sm:grid-cols-3 lg:grid-cols-5 lg:divide-x [&>*]:border-line max-lg:[&>*]:border-b">
        <Stat label="Open alerts" value={num(overview.alerts_open)} sub={`${critical} critical`} tone={critical ? 'critical' : undefined} />
        <Stat label="Active incidents" value={num(overview.incidents_open)} sub={`${overview.critical_incidents} critical`} />
        <Stat label="Events processed" value={compact(overview.events_total)} sub={`${num(Math.round(overview.events_per_second))} events/s`} />
        <Stat
          label="Events per alert"
          value={overview.events_per_alert ? compact(overview.events_per_alert) : '—'}
          sub="Alert volume reduction"
        />
        <Stat
          label="Median time to detect"
          value={duration(overview.median_time_to_detect)}
          sub={runsDone ? 'Across simulated attacks' : 'Run a simulation to measure'}
        />
      </Card>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader
            title="Telemetry volume"
            hint="Events per simulated minute, last 60 minutes"
            action={
              <Legend
                items={[
                  ...LAYERS.map((l) => ({ label: LAYER_LABEL[l], color: layerColorVar[l] })),
                  { label: 'Alert raised', color: 'var(--color-sev-critical)', shape: 'dot' as const },
                ]}
              />
            }
          />
          <div className="px-3 pt-3 pb-2">
            <ActivityChart data={overview.series} />
          </div>
        </Card>

        <Card>
          <CardHeader title="Open alerts by severity" hint={`${num(overview.alerts_open)} open of ${num(overview.alerts_total)} total`} />
          <div className="space-y-5 p-4">
            <BarList
              items={SEVERITY_ORDER.map((s) => ({
                key: s,
                label: (
                  <span className="flex items-center gap-2">
                    <SeverityDot severity={s} />
                    {severityLabel(s)}
                  </span>
                ),
                value: overview.open_by_severity[s] ?? 0,
                color: SEV_COLOR[s],
              }))}
              format={num}
            />
            <div>
              <p className="mb-2 text-xs font-medium text-ink-2">By technique</p>
              {Object.keys(overview.open_by_threat).length === 0 ? (
                <p className="text-xs text-ink-3">No open alerts.</p>
              ) : (
                <BarList
                  items={Object.entries(overview.open_by_threat)
                    .sort((a, b) => (b[1] ?? 0) - (a[1] ?? 0))
                    .map(([k, v]) => ({ key: k, label: THREAT_LABEL[k as keyof typeof THREAT_LABEL], value: v ?? 0, color: 'var(--color-ink-2)' }))}
                  format={num}
                />
              )}
            </div>
          </div>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader
            title="Incidents"
            hint="Alerts linked by host, account and destination across layers"
            action={<a href="#/incidents" className="flex items-center gap-1 text-xs text-ink-3 hover:text-ink">View all<ArrowUpRight size={12} /></a>}
          />
          {incidents.length === 0 ? (
            <Empty icon={ShieldCheck} title="No correlated incidents" body="Launch the full kill-chain scenario to watch alerts from different hosts and layers join into one incident." />
          ) : (
            <ul className="divide-y divide-line">
              <AnimatePresence initial={false}>
                {incidents.slice(0, 4).map((inc) => (
                  <motion.li key={inc.id} layout initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={spring}>
                    <a href={`#/incidents/${inc.id}`} className="flex items-center gap-4 px-4 py-3.5 transition-colors hover:bg-subtle/60">
                      <RiskRing value={inc.risk} />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <SeverityBadge severity={inc.severity} />
                          <span className="font-mono text-[11px] text-ink-3">{inc.id}</span>
                          <span className="text-[11px] text-ink-3">· {inc.alert_count} alerts · {ago(inc.last_seen, overview.now)}</span>
                        </div>
                        <p className="mt-1 truncate text-[13px] font-medium">{inc.title}</p>
                        <div className="mt-2 max-w-md">
                          <KillChain reached={inc.tactics} />
                        </div>
                      </div>
                    </a>
                  </motion.li>
                ))}
              </AnimatePresence>
            </ul>
          )}
        </Card>

        <Card>
          <CardHeader title="Hosts at risk" hint="Ranked by open alert severity and confidence" />
          {overview.top_entities.length === 0 ? (
            <Empty icon={ShieldCheck} title="All quiet" body="No host has open alerts." />
          ) : (
            <ul className="divide-y divide-line">
              {overview.top_entities.map((e) => (
                <li key={e.ip}>
                  <a href="#/alerts" onClick={() => setAlertQuery(e.ip)} className="flex items-center gap-3 px-4 py-2.5 hover:bg-subtle/60">
                    <SeverityDot severity={e.severity} />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-[13px] font-medium">{e.hostname ?? e.ip}</p>
                      <p className="truncate text-[11px] text-ink-3"><Mono>{e.ip}</Mono> · {e.role}</p>
                    </div>
                    <span className="tnum text-xs text-ink-2">{e.alerts} alert{e.alerts === 1 ? '' : 's'}</span>
                  </a>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-5">
        <Card className="xl:col-span-2">
          <CardHeader
            title="Latest alerts"
            action={<a href="#/alerts" className="flex items-center gap-1 text-xs text-ink-3 hover:text-ink">Triage<ArrowUpRight size={12} /></a>}
          />
          {alerts.length === 0 ? (
            <Empty icon={BellRing} title="No open alerts" body="Background traffic is being scored. Alerts appear here as soon as something looks wrong." />
          ) : (
            <ul className="divide-y divide-line">
              <AnimatePresence initial={false}>
                {alerts.slice(0, 7).map((a) => (
                  <motion.li key={a.id} layout="position" initial={{ opacity: 0, backgroundColor: 'rgba(91,91,214,0.08)' }} animate={{ opacity: 1, backgroundColor: 'rgba(91,91,214,0)' }} transition={{ duration: 0.8 }}>
                    <a href={`#/alerts/${a.id}`} className="flex items-center gap-3 px-4 py-2.5 hover:bg-subtle/60">
                      <SeverityBadge severity={a.severity} compact />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-[13px]">
                          <span className="font-medium">{a.title}</span>
                          <span className="text-ink-3"> · {a.hostname ?? a.entity}</span>
                        </p>
                      </div>
                      <span className="tnum shrink-0 text-[11px] text-ink-3">{ago(a.last_seen, overview.now)}</span>
                    </a>
                  </motion.li>
                ))}
              </AnimatePresence>
            </ul>
          )}
        </Card>

        <Card className="xl:col-span-3">
          <CardHeader
            title={<span className="flex items-center gap-2"><Radio size={13} className="text-good" />Live telemetry</span>}
            hint="A sample of raw events as the sensors report them"
          />
          <TelemetryTable />
        </Card>
      </div>
    </div>
  )
}

function describe(e: Telemetry): string {
  switch (e.kind) {
    case 'http':
      return `${e.method ?? 'GET'} ${e.path ?? '/'} → ${e.status ?? ''}${e.user ? ` (${e.user})` : ''}`
    case 'auth':
      return `logon ${e.outcome} · ${e.user ?? '?'}`
    case 'process':
      return e.process ?? 'process start'
    default:
      return `:${e.dst_port ?? 0} ↑${bytes(e.bytes_out ?? 0)} ↓${bytes(e.bytes_in ?? 0)}`
  }
}

function TelemetryTable() {
  const telemetry = useStore((s) => s.telemetry)
  const rows = telemetry.slice(-12).reverse()
  if (!rows.length) return <Empty icon={Radio} title="No telemetry yet" body="The stream starts when the engine is running." />
  return (
    <div className="overflow-x-auto scroll-thin">
      <table className="w-full min-w-[560px] text-left">
        <tbody className="divide-y divide-line">
          {rows.map((e, i) => (
            <tr key={`${e.ts}-${i}`} className={clsx('font-mono text-[11.5px]', e.threat && 'bg-[#fcf0f0]')}>
              <td className="tnum py-1.5 pr-3 pl-4 whitespace-nowrap text-ink-3">{clock(e.ts)}</td>
              <td className="py-1.5 pr-3">
                <span className="flex items-center gap-1.5 text-ink-2">
                  <span className="size-1.5 rounded-full" style={{ background: layerColorVar[e.layer] }} />
                  {e.kind}
                </span>
              </td>
              <td className="py-1.5 pr-3 whitespace-nowrap text-ink">{e.src_ip}</td>
              <td className="py-1.5 pr-3 whitespace-nowrap text-ink-2">→ {e.dst_ip}</td>
              <td className="max-w-[240px] truncate py-1.5 pr-4 text-ink-2">
                {e.threat ? <span className="mr-2 font-sans font-medium text-[#b42b2b]">{THREAT_LABEL[e.threat]}</span> : null}
                {describe(e)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

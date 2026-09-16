import clsx from 'clsx'
import { CheckCircle2, CircleDashed, Clock, FlaskConical, Play, RotateCcw, ShieldAlert, Square, XCircle } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useMemo, useState } from 'react'
import { Button, Card, CardHeader, Empty, LayerTag, PageHeader, Segmented, spring } from '../components/ui'
import { api } from '../lib/api'
import { duration, num, THREAT_LABEL } from '../lib/format'
import { useStore } from '../lib/store'
import type { Scenario, SimulationRun } from '../lib/types'

const DIFFICULTY_TONE: Record<string, string> = {
  Basic: 'text-ink-2 bg-subtle',
  Intermediate: 'text-[#8a5d00] bg-[#fdf7e8]',
  Advanced: 'text-[#b42b2b] bg-[#fcf0f0]',
  Evasive: 'text-accent bg-accent-soft',
  Novel: 'text-accent bg-accent-soft',
  'False-positive test': 'text-good-ink bg-[#f0f8f0]',
}

export default function Simulate() {
  const scenarios = useStore((s) => s.scenarios)
  const runsMap = useStore((s) => s.runs)
  const overview = useStore((s) => s.overview)
  const toast = useStore((s) => s.toast)
  const upsertRun = useStore((s) => s.upsertRun)
  const runs = useMemo(() => Object.values(runsMap).sort((a, b) => b.started_at - a.started_at), [runsMap])

  const launch = async (s: Scenario, intensity: number) => {
    try {
      const run = await api.launch(s.id, intensity)
      upsertRun(run)
      toast({ tone: 'info', title: 'Scenario launched', body: `${s.name}. Injecting ${num(run.total_events)} events.` })
    } catch (e) {
      toast({ tone: 'critical', title: 'Launch failed', body: e instanceof Error ? e.message : String(e) })
    }
  }

  return (
    <div>
      <PageHeader
        title="Simulation"
        description="Inject attack campaigns into live background traffic and score the engine against ground truth. Every run uses fresh attacker IPs, victims, rates and timing."
        actions={
          <>
            <label className="flex h-8 cursor-pointer items-center gap-2 rounded-lg border border-line-strong bg-surface px-2.5 text-[13px] shadow-card">
              <input
                type="checkbox"
                className="accent-[var(--color-ink)]"
                checked={overview?.ambient ?? true}
                onChange={(e) => void api.updateSettings({ ambient: e.target.checked })}
              />
              Background traffic
            </label>
            <Button
              variant="ghost"
              icon={RotateCcw}
              onClick={() => void api.reset().then(() => toast({ tone: 'info', title: 'Engine reset', body: 'Alerts, incidents and runs cleared.' }))}
            >
              Reset engine
            </Button>
          </>
        }
      />

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {scenarios.map((s, i) => (
          <motion.div key={s.id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ ...spring, delay: i * 0.03 }}>
            <ScenarioCard scenario={s} onLaunch={launch} running={runs.some((r) => r.scenario === s.id && r.status === 'running')} />
          </motion.div>
        ))}
      </div>

      <Card className="mt-6">
        <CardHeader
          title="Runs"
          hint={`Simulated clock runs at ${overview?.speed ?? 30}× real time. Detection times are in simulated seconds.`}
        />
        {runs.length === 0 ? (
          <Empty icon={FlaskConical} title="No runs yet" body="Launch a scenario above. The scorecard shows when each attack stage started and when the engine first alerted on it." />
        ) : (
          <ul className="divide-y divide-line">
            <AnimatePresence initial={false}>
              {runs.map((r) => (
                <motion.li key={r.id} layout initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} transition={spring}>
                  <RunRow run={r} />
                </motion.li>
              ))}
            </AnimatePresence>
          </ul>
        )}
      </Card>
    </div>
  )
}

function ScenarioCard({ scenario: s, onLaunch, running }: { scenario: Scenario; onLaunch: (s: Scenario, i: number) => Promise<void>; running: boolean }) {
  const [intensity, setIntensity] = useState(1)
  const [busy, setBusy] = useState(false)
  return (
    <div className="flex h-full flex-col rounded-xl border border-line bg-surface p-4 shadow-card transition-[border-color,box-shadow] hover:border-line-strong">
      <div className="flex items-start justify-between gap-2">
        <h3 className="text-[14px] font-medium">{s.name}</h3>
        <span className={clsx('shrink-0 rounded-md px-1.5 py-0.5 text-[11px] font-medium', DIFFICULTY_TONE[s.difficulty] ?? 'bg-subtle text-ink-2')}>
          {s.difficulty}
        </span>
      </div>
      <p className="mt-1.5 text-[13px] leading-relaxed text-ink-2">{s.summary}</p>
      <div className="mt-3 flex flex-wrap gap-1">
        {s.stages.length ? (
          s.stages.map((st, i) => (
            <span key={st} className="flex items-center gap-1 text-[11px] text-ink-2">
              {i > 0 && <span className="text-ink-3">→</span>}
              <span className="rounded border border-line px-1.5 py-0.5">{THREAT_LABEL[st]}</span>
            </span>
          ))
        ) : (
          <span className="rounded border border-dashed border-line-strong px-1.5 py-0.5 text-[11px] text-ink-3">No malicious stages</span>
        )}
      </div>
      <p className="mt-3 text-xs text-ink-3"><span className="font-medium text-ink-2">Expected: </span>{s.expectation}</p>
      <div className="flex-1" />
      <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-line pt-3">
        {s.layers.map((l) => <LayerTag key={l} layer={l} />)}
        <span className="flex items-center gap-1 text-[11px] text-ink-3"><Clock size={11} />~{s.duration_min} sim-min</span>
      </div>
      <div className="mt-3 flex items-center gap-2">
        <Segmented
          label={`Intensity ${s.id}`}
          value={intensity}
          onChange={setIntensity}
          options={[
            { value: 0.6, label: 'Subtle' },
            { value: 1, label: 'Normal' },
            { value: 1.6, label: 'Loud' },
          ]}
        />
        <div className="flex-1" />
        <Button
          variant="primary"
          icon={Play}
          disabled={busy}
          onClick={async () => {
            setBusy(true)
            await onLaunch(s, intensity)
            setBusy(false)
          }}
        >
          {running ? 'Launch again' : 'Launch'}
        </Button>
      </div>
    </div>
  )
}

function RunRow({ run: r }: { run: SimulationRun }) {
  const benign = r.detected === null
  const outcome = r.status === 'running'
    ? { icon: CircleDashed, label: 'Running', cls: 'text-accent' }
    : benign
      ? r.false_alerts === 0
        ? { icon: CheckCircle2, label: 'No false alerts', cls: 'text-good-ink' }
        : { icon: XCircle, label: `${r.false_alerts} false alert${r.false_alerts === 1 ? '' : 's'}`, cls: 'text-[#8a5d00]' }
      : r.detected
        ? { icon: CheckCircle2, label: `Detected in ${duration(r.time_to_detect)}`, cls: 'text-good-ink' }
        : { icon: XCircle, label: r.status === 'stopped' ? 'Stopped' : 'Missed', cls: 'text-[#b42b2b]' }
  const Icon = outcome.icon
  return (
    <div className="px-4 py-4">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="font-mono text-[11px] text-ink-3">{r.id}</span>
        <span className="text-[13px] font-medium">{r.name}</span>
        <span className={clsx('flex items-center gap-1 text-xs font-medium', outcome.cls)}>
          <Icon size={13} className={r.status === 'running' ? 'animate-spin [animation-duration:2.5s]' : ''} />
          {outcome.label}
        </span>
        <div className="flex-1" />
        {r.incident_ids.map((id) => (
          <a key={id} href={`#/incidents/${id}`} className="flex items-center gap-1 rounded-md border border-line px-1.5 py-0.5 text-[11px] text-ink-2 hover:border-line-strong hover:text-ink">
            <ShieldAlert size={11} />{id}
          </a>
        ))}
        <span className="text-[11px] text-ink-3">{r.alert_ids.length} alerts</span>
        {r.status === 'running' && (
          <Button size="sm" variant="ghost" icon={Square} onClick={() => void api.stopRun(r.id)}>Stop</Button>
        )}
      </div>

      <div className="mt-2.5 flex items-center gap-3">
        <div className="h-1 flex-1 overflow-hidden rounded-full bg-subtle">
          <motion.div
            className={clsx('h-full rounded-full', r.status === 'stopped' ? 'bg-ink-3' : 'bg-ink')}
            initial={false}
            animate={{ width: `${r.progress * 100}%` }}
            transition={{ duration: 0.4, ease: 'easeOut' }}
          />
        </div>
        <span className="tnum w-28 text-right text-[11px] text-ink-3">{num(r.emitted)} / {num(r.total_events)} events</span>
      </div>

      {r.stages.length > 0 && (
        <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
          {r.stages.map((st) => {
            const started = r.emitted > 0 && st.started_at <= (r.ended_at ?? Number.POSITIVE_INFINITY)
            return (
              <div
                key={st.threat}
                className={clsx(
                  'rounded-lg border px-2.5 py-2 transition-colors',
                  st.detected_at !== null ? 'border-[#cfe8cf] bg-[#f5fbf5]' : 'border-line bg-surface',
                )}
              >
                <p className="flex items-center justify-between text-xs font-medium">
                  {st.title}
                  {st.detected_at !== null ? <CheckCircle2 size={13} className="text-good" /> : <CircleDashed size={13} className="text-ink-3" />}
                </p>
                <p className="mt-0.5 text-[11px] text-ink-3">{st.tactic}</p>
                <p className="tnum mt-1.5 text-[11px]">
                  {st.detected_at !== null ? (
                    <span className="text-good-ink">Alerted after {duration(st.time_to_detect)}</span>
                  ) : (
                    <span className="text-ink-3">{started && r.status !== 'running' ? 'Not detected' : 'Waiting…'}</span>
                  )}
                </p>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

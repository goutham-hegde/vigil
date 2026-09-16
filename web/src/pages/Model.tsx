import { BrainCircuit } from 'lucide-react'
import { useEffect, useState } from 'react'
import { BarList, ConfusionMatrix } from '../components/charts'
import { Card, CardHeader, Empty, Mono, PageHeader, Skeleton, Stat } from '../components/ui'
import { api } from '../lib/api'
import { compact, duration, num, pct, THREAT_LABEL } from '../lib/format'
import type { ModelInfo } from '../lib/types'

const SCENARIO_NAMES: Record<string, string> = {
  intrusion_chain: 'Full intrusion kill chain',
  credential_stuffing: 'Credential stuffing',
  c2_exfil: 'C2 implant and exfiltration',
  low_and_slow: 'Low-and-slow guessing',
  benign_noise: 'Benign look-alikes',
  dns_tunnel: 'DNS tunnelling (held out)',
}

export default function Model() {
  const [info, setInfo] = useState<ModelInfo | null>(null)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    api.model().then(setInfo).catch((e) => setError(String(e)))
  }, [])

  if (error) return <Empty icon={BrainCircuit} title="Could not load the model card" body={error} />
  if (!info) return <div className="space-y-4"><Skeleton className="h-8 w-40" /><Skeleton className="h-24" /><Skeleton className="h-96" /></div>

  const { meta, metrics } = info
  const header = (
    <PageHeader
      title="Model"
      description="How the detector was trained and how it scored on a held-out simulation run it never saw: different day, attackers, victims and timings."
    />
  )
  if (!metrics) {
    return <div>{header}<Empty icon={BrainCircuit} title="No evaluation report" body="Run `python -m vigil.train` to produce models/metrics.json." /></div>
  }
  const ev = metrics.event_level
  const pl = metrics.pipeline
  const perClass = Object.entries(ev.per_class)

  return (
    <div>
      {header}

      <Card className="mb-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 lg:divide-x lg:divide-line max-lg:[&>*]:border-b max-lg:[&>*]:border-line">
        <Stat label="Macro F1 (events)" value={ev.macro_f1.toFixed(3)} sub="6 classes, held-out run" />
        <Stat label="Malicious precision" value={pct(ev.malicious_precision, 1)} sub={`Recall ${pct(ev.malicious_recall, 1)}`} />
        <Stat label="Benign events flagged" value={pct(ev.benign_false_positive_rate, 3)} sub={`Look-alikes: ${pct(ev.lookalike_false_positive_rate, 3)}`} />
        <Stat label="False alerts / hour" value={pl.false_alerts_per_hour.toFixed(1)} sub={`${pl.false_alerts} of ${pl.alerts} alerts`} />
        <Stat label="Alert precision" value={pct(pl.alert_precision, 1)} sub={`${compact(pl.events_per_alert)} events per alert`} />
        <Stat label="Calibration error" value={ev.ece_calibrated.toFixed(3)} sub={`ECE, T = ${meta.temperature.toFixed(2)}`} />
      </Card>

      <div className="grid gap-4 xl:grid-cols-5">
        <Card className="xl:col-span-3">
          <CardHeader title="Detection by scenario" hint={`Full pipeline replayed over ${pl.hours} h of test telemetry (${compact(pl.events)} events)`} />
          <div className="overflow-x-auto scroll-thin">
            <table className="w-full min-w-[620px] text-left text-[13px]">
              <thead className="border-b border-line bg-subtle/50 text-[11px] text-ink-3">
                <tr>
                  <th className="px-4 py-2 font-medium">Scenario</th>
                  <th className="px-3 py-2 text-right font-medium">Runs</th>
                  <th className="px-3 py-2 text-right font-medium">Detected</th>
                  <th className="px-3 py-2 text-right font-medium">Stage recall</th>
                  <th className="px-3 py-2 text-right font-medium">Median TTD</th>
                  <th className="px-3 py-2 text-right font-medium">Alerts</th>
                  <th className="px-4 py-2 font-medium">Detector</th>
                </tr>
              </thead>
              <tbody className="tnum divide-y divide-line">
                {Object.entries(pl.scenarios).map(([k, s]) => (
                  <tr key={k}>
                    <td className="px-4 py-2.5">{SCENARIO_NAMES[k] ?? k}</td>
                    <td className="px-3 py-2.5 text-right text-ink-2">{s.runs}</td>
                    <td className="px-3 py-2.5 text-right">
                      {s.detected_runs === null ? <span className="text-ink-3">n/a</span> : `${s.detected_runs}/${s.runs}`}
                    </td>
                    <td className="px-3 py-2.5 text-right text-ink-2">{s.stage_recall === null ? '—' : pct(s.stage_recall)}</td>
                    <td className="px-3 py-2.5 text-right text-ink-2">{duration(s.median_time_to_detect_s)}</td>
                    <td className="px-3 py-2.5 text-right">
                      {k === 'benign_noise' ? <span className={s.alerts ? 'text-[#8a5d00]' : 'text-good-ink'}>{s.alerts} false</span> : s.alerts}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-ink-3">
                      {Object.entries(s.detectors).map(([d, n]) => `${d} ${n}`).join(' · ') || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {pl.false_alert_examples.length > 0 && (
            <div className="border-t border-line px-4 py-3">
              <p className="mb-2 text-xs font-medium text-ink-2">Largest false alerts on the test run</p>
              <ul className="flex flex-wrap gap-1.5">
                {pl.false_alert_examples.map((f, i) => (
                  <li key={i} className="rounded-md border border-line px-2 py-1 text-[11px] text-ink-2">
                    {THREAT_LABEL[f.threat as keyof typeof THREAT_LABEL] ?? f.threat} on <Mono>{f.entity}</Mono>
                    <span className="text-ink-3"> · {f.events} event{f.events === 1 ? '' : 's'} · {Math.round(f.confidence * 100)}%</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Card>

        <Card className="xl:col-span-2">
          <CardHeader title="What the classifier relies on" hint="Share of total split gain, top 12 features" />
          <div className="p-4">
            <BarList
              items={metrics.feature_importance.slice(0, 12).map((f) => ({ key: f.feature, label: f.label, value: f.gain, color: 'var(--color-net)' }))}
              format={(v) => pct(v, 1)}
            />
          </div>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-5">
        <Card className="xl:col-span-3">
          <CardHeader title="Confusion matrix" hint="Event level, held-out run, DNS tunnel events excluded (not a trained class)" />
          <div className="p-4">
            <ConfusionMatrix labels={ev.confusion_matrix.labels} matrix={ev.confusion_matrix.matrix} />
          </div>
        </Card>
        <Card className="xl:col-span-2">
          <CardHeader title="Per-class scores" />
          <table className="w-full text-left text-[13px]">
            <thead className="border-b border-line text-[11px] text-ink-3">
              <tr>
                <th className="px-4 py-2 font-medium">Class</th>
                <th className="px-2 py-2 text-right font-medium">Precision</th>
                <th className="px-2 py-2 text-right font-medium">Recall</th>
                <th className="px-2 py-2 text-right font-medium">F1</th>
                <th className="px-4 py-2 text-right font-medium">Support</th>
              </tr>
            </thead>
            <tbody className="tnum divide-y divide-line">
              {perClass.map(([k, v]) => (
                <tr key={k}>
                  <td className="px-4 py-2">{THREAT_LABEL[k as keyof typeof THREAT_LABEL] ?? k}</td>
                  <td className="px-2 py-2 text-right">{v.precision.toFixed(3)}</td>
                  <td className="px-2 py-2 text-right">{v.recall.toFixed(3)}</td>
                  <td className="px-2 py-2 text-right font-medium">{v['f1-score'].toFixed(3)}</td>
                  <td className="px-4 py-2 text-right text-ink-3">{num(v.support)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1.5 border-t border-line px-4 py-3 text-xs">
            <dt className="text-ink-3">Version</dt><dd className="text-right font-mono">{meta.version}</dd>
            <dt className="text-ink-3">Trees</dt><dd className="tnum text-right">{meta.best_iteration} × 6 classes</dd>
            <dt className="text-ink-3">Alert threshold</dt><dd className="tnum text-right">P(malicious) ≥ {meta.threshold.toFixed(2)}</dd>
            <dt className="text-ink-3">Features</dt><dd className="tnum text-right">{meta.features.length}</dd>
            {Object.entries(metrics.data).map(([name, d]) => (
              <div key={name} className="contents">
                <dt className="text-ink-3 capitalize">{name} data</dt>
                <dd className="tnum text-right">{d.hours} h · {compact(d.events)} events</dd>
              </div>
            ))}
          </dl>
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader title="Limitations" />
        <ul className="list-disc space-y-1.5 py-4 pr-4 pl-8 text-[13px] leading-relaxed text-ink-2">
          <li>All data is simulated. Real telemetry is messier, so treat these scores as an upper bound and as a regression baseline, not a production estimate.</li>
          <li>Event-level scores count every event of an attack, including early ones that look benign in isolation. Scenario-level detection and false alerts per hour matter more to an analyst.</li>
          <li>Asset roles (workstation, server, sanctioned IT tooling) come from the inventory and are model features. A compromised scanner or backup server would be under-scored.</li>
          <li>The isolation forest is tuned to stay quiet. On this test run it raised no alerts; the held-out DNS tunnel was caught by the classifier through its exfiltration features.</li>
          <li>Analyst verdicts are written to <Mono>data/feedback.jsonl</Mono>, but retraining from them is a manual step.</li>
        </ul>
      </Card>
    </div>
  )
}

export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type Layer = 'network' | 'endpoint' | 'application'
export type AlertStatus = 'open' | 'acknowledged' | 'resolved' | 'false_positive'
export type Threat = 'recon' | 'brute_force' | 'lateral_movement' | 'c2_beacon' | 'exfiltration' | 'anomaly'

export interface Mitre {
  id: string
  name: string
}

export interface AlertSummary {
  id: string
  threat: Threat
  title: string
  tactic: string
  stage: number
  mitre: Mitre[]
  severity: Severity
  confidence: number
  detector: 'supervised' | 'anomaly'
  status: AlertStatus
  entity: string
  hostname: string | null
  role: string
  first_seen: number
  last_seen: number
  event_count: number
  layers: Layer[]
  summary: string
  incident_id: string | null
  target_count: number
  ground_truth: 'malicious' | 'benign'
  revision: number
}

export interface Explanation {
  feature: string
  label: string
  value: string
  weight: number
  method: 'shap' | 'z'
}

export type Playbook = Record<'contain' | 'investigate' | 'remediate', string[]>

export interface Telemetry {
  ts: number
  layer: Layer
  kind: string
  src_ip: string
  dst_ip: string
  dst_port?: number
  bytes_out?: number
  bytes_in?: number
  duration?: number
  user?: string
  outcome?: string
  method?: string
  path?: string
  status?: number
  process?: string
  threat?: Threat | null
}

export interface AlertDetail extends AlertSummary {
  targets: { ip: string; count: number }[]
  ports: number[]
  users: string[]
  compromised_users: string[]
  bytes_out: number
  auth_failures: number
  layer_counts: Partial<Record<Layer, number>>
  explanation: Explanation[]
  class_probs: Record<string, number>
  evidence: Telemetry[]
  playbook: Playbook
  notes: { ts: number; text: string; status: AlertStatus }[]
}

export interface IncidentStage {
  tactic: string
  threat: Threat
  title: string
  stage: number
  first_seen: number
  alert_ids: string[]
}

export interface Incident {
  id: string
  status: string
  created_at: number
  alert_ids: string[]
  title: string
  severity: Severity
  risk: number
  confidence: number
  first_seen: number
  last_seen: number
  tactics: string[]
  stages: IncidentStage[]
  entities: { ip: string; hostname: string | null; role: string }[]
  users: string[]
  layers: Layer[]
  mitre: string[]
  story: { ts: number; alert_id: string; threat: Threat; text: string }[]
  playbook: Playbook
  alert_count: number
  alerts?: AlertSummary[]
  deleted?: boolean
}

export interface SeriesPoint {
  t: number
  network: number
  endpoint: number
  application: number
  flagged: number
  alerts: number
}

export interface Overview {
  now: number
  speed: number
  ambient: boolean
  paused: boolean
  events_total: number
  events_per_second: number
  flagged_events: number
  layer_totals: Record<Layer, number>
  alerts_total: number
  alerts_open: number
  open_by_severity: Partial<Record<Severity, number>>
  open_by_threat: Partial<Record<Threat, number>>
  alerts_by_status: Partial<Record<AlertStatus, number>>
  incidents_open: number
  critical_incidents: number
  events_per_alert: number | null
  median_time_to_detect: number | null
  active_runs: number
  top_entities: { ip: string; hostname: string | null; role: string; alerts: number; severity: Severity; score: number }[]
  model_version: string
  series: SeriesPoint[]
}

export interface Scenario {
  id: string
  name: string
  summary: string
  stages: Threat[]
  layers: Layer[]
  duration_min: number
  difficulty: string
  expectation: string
  held_out?: boolean
}

export interface RunStage {
  threat: Threat
  title: string
  tactic: string
  started_at: number
  detected_at: number | null
  time_to_detect: number | null
}

export interface SimulationRun {
  id: string
  campaign_id: string
  scenario: string
  name: string
  status: 'running' | 'completed' | 'stopped'
  intensity: number
  started_at: number
  ended_at: number | null
  sim_start: number
  sim_end: number
  total_events: number
  emitted: number
  progress: number
  entities: string[]
  stages: RunStage[]
  alert_ids: string[]
  incident_ids: string[]
  false_alerts: number
  time_to_detect: number | null
  detected: boolean | null
}

export interface Settings {
  speed: number
  ambient: boolean
  paused: boolean
}

export interface ScenarioStats {
  runs: number
  alerts: number
  detected_runs: number | null
  stage_recall: number | null
  median_time_to_detect_s: number | null
  runs_with_incident: number
  detectors: Record<string, number>
}

export interface ModelInfo {
  meta: {
    version: string
    trained_at: string
    classes: string[]
    features: string[]
    temperature: number
    threshold: number
    anomaly_threshold: number
    best_iteration: number
    quick: boolean
  }
  metrics: null | {
    data: Record<string, { hours: number; events: number; campaigns: Record<string, number>; class_counts: Record<string, number> }>
    event_level: {
      macro_f1: number
      per_class: Record<string, { precision: number; recall: number; 'f1-score': number; support: number }>
      confusion_matrix: { labels: string[]; matrix: number[][] }
      malicious_precision: number
      malicious_recall: number
      malicious_f1: number
      benign_false_positive_rate: number
      lookalike_false_positive_rate: number
      ece_uncalibrated: number
      ece_calibrated: number
    }
    pipeline: {
      hours: number
      events: number
      alerts: number
      false_alerts: number
      false_alerts_per_hour: number
      alert_precision: number
      events_per_alert: number
      incidents: number
      false_alert_examples: { threat: string; entity: string; detector: string; confidence: number; events: number }[]
      scenarios: Record<string, ScenarioStats>
    }
    feature_importance: { feature: string; label: string; gain: number }[]
  }
  features: { name: string; label: string; kind: string }[]
}

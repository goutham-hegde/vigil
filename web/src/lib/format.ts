import type { Layer, Severity, Threat } from './types'

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low']
export const SEVERITY_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 }
export const LAYERS: Layer[] = ['network', 'endpoint', 'application']

export const LAYER_LABEL: Record<Layer, string> = {
  network: 'Network',
  endpoint: 'Endpoint',
  application: 'Application',
}

export const THREAT_LABEL: Record<Threat | 'benign', string> = {
  benign: 'Benign',
  recon: 'Recon',
  brute_force: 'Brute force',
  lateral_movement: 'Lateral movement',
  c2_beacon: 'C2 beacon',
  exfiltration: 'Exfiltration',
  anomaly: 'Anomaly',
}

const timeFmt = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'UTC' })
const shortFmt = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' })

export const clock = (ts: number) => timeFmt.format(ts * 1000)
export const clockShort = (ts: number) => shortFmt.format(ts * 1000)

export function ago(ts: number, now: number): string {
  const s = Math.max(0, now - ts)
  if (s < 60) return `${Math.floor(s)}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  return `${Math.floor(s / 3600)}h ago`
}

export function duration(s: number | null | undefined): string {
  if (s === null || s === undefined) return '—'
  if (s < 1) return '<1s'
  if (s < 90) return `${Math.round(s)}s`
  if (s < 5400) return `${Math.round(s / 60)}m`
  return `${(s / 3600).toFixed(1)}h`
}

export function bytes(n: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024
    i++
  }
  return `${i ? n.toFixed(1) : n.toFixed(0)} ${units[i]}`
}

export const num = (n: number) => n.toLocaleString('en-US')

export function compact(n: number): string {
  if (n < 1000) return String(n)
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)}k`
  return `${(n / 1_000_000).toFixed(1)}M`
}

export const pct = (x: number, digits = 0) => `${(x * 100).toFixed(digits)}%`

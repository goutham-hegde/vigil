import type {
  AlertDetail, AlertStatus, AlertSummary, Incident, ModelInfo, Overview, Scenario, Settings, SimulationRun,
} from './types'

const BASE = import.meta.env.VITE_API_URL ?? ''

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  })
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
    } catch {
      /* body was not JSON */
    }
    throw new ApiError(res.status, detail)
  }
  return res.json() as Promise<T>
}

const json = (method: string, body: unknown): RequestInit => ({ method, body: JSON.stringify(body) })

export const api = {
  overview: () => request<Overview>('/api/overview'),
  alerts: () => request<AlertSummary[]>('/api/alerts?limit=2000'),
  alert: (id: string) => request<AlertDetail>(`/api/alerts/${id}`),
  setAlertStatus: (id: string, status: AlertStatus, note?: string) =>
    request<AlertDetail>(`/api/alerts/${id}`, json('PATCH', { status, note })),
  incidents: () => request<Incident[]>('/api/incidents'),
  incident: (id: string) => request<Incident>(`/api/incidents/${id}`),
  scenarios: () => request<Scenario[]>('/api/scenarios'),
  runs: () => request<SimulationRun[]>('/api/simulations'),
  launch: (scenario: string, intensity: number) =>
    request<SimulationRun>('/api/simulations', json('POST', { scenario, intensity })),
  stopRun: (id: string) => request<SimulationRun>(`/api/simulations/${id}/stop`, { method: 'POST' }),
  updateSettings: (patch: Partial<Settings>) => request<Settings>('/api/settings', json('PATCH', patch)),
  reset: () => request<{ status: string }>('/api/reset', { method: 'POST' }),
  model: () => request<ModelInfo>('/api/model'),
  streamUrl: () => `${BASE}/api/stream`,
}

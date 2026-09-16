import { create } from 'zustand'
import { api } from './api'
import type { AlertSummary, Incident, Overview, Scenario, Settings, SimulationRun, Telemetry } from './types'

export interface Toast {
  id: number
  tone: 'critical' | 'info' | 'success'
  title: string
  body?: string
  href?: string
}

type Connection = 'connecting' | 'live' | 'offline'

interface State {
  connection: Connection
  overview: Overview | null
  alerts: Record<string, AlertSummary>
  incidents: Record<string, Incident>
  runs: Record<string, SimulationRun>
  scenarios: Scenario[]
  telemetry: Telemetry[]
  toasts: Toast[]
  error: string | null
  paletteOpen: boolean
  alertQuery: string
  bootstrap: () => Promise<void>
  connect: () => () => void
  applySettings: (s: Settings) => void
  upsertAlert: (a: AlertSummary) => void
  upsertRun: (r: SimulationRun) => void
  toast: (t: Omit<Toast, 'id'>) => void
  dismiss: (id: number) => void
  setPalette: (open: boolean) => void
  setAlertQuery: (q: string) => void
}

let toastId = 0
const byId = <T extends { id: string }>(items: T[]) => Object.fromEntries(items.map((i) => [i.id, i]))

export const useStore = create<State>((set, get) => ({
  connection: 'connecting',
  overview: null,
  alerts: {},
  incidents: {},
  runs: {},
  scenarios: [],
  telemetry: [],
  toasts: [],
  error: null,
  paletteOpen: false,
  alertQuery: '',

  bootstrap: async () => {
    try {
      const [overview, alerts, incidents, runs, scenarios] = await Promise.all([
        api.overview(), api.alerts(), api.incidents(), api.runs(), api.scenarios(),
      ])
      set({ overview, alerts: byId(alerts), incidents: byId(incidents), runs: byId(runs), scenarios, error: null })
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) })
    }
  },

  connect: () => {
    let source: EventSource | null = null
    let retry: ReturnType<typeof setTimeout> | undefined
    let closed = false

    const open = () => {
      source = new EventSource(api.streamUrl())
      source.addEventListener('hello', () => {
        set({ connection: 'live' })
        void get().bootstrap()
      })
      source.addEventListener('tick', (e) => set({ overview: JSON.parse(e.data) }))
      source.addEventListener('alert', (e) => get().upsertAlert(JSON.parse(e.data)))
      source.addEventListener('incident', (e) => {
        const inc: Incident = JSON.parse(e.data)
        const prev = get().incidents[inc.id]
        set((s) => {
          const incidents = { ...s.incidents }
          if (inc.deleted) delete incidents[inc.id]
          else incidents[inc.id] = inc
          return { incidents }
        })
        if (!inc.deleted && inc.severity === 'critical' && prev?.severity !== 'critical') {
          get().toast({ tone: 'critical', title: 'Critical incident', body: inc.title, href: `#/incidents/${inc.id}` })
        }
      })
      source.addEventListener('run', (e) => get().upsertRun(JSON.parse(e.data)))
      source.addEventListener('telemetry', (e) => set({ telemetry: JSON.parse(e.data).events }))
      source.addEventListener('settings', (e) => get().applySettings(JSON.parse(e.data)))
      source.addEventListener('reset', () => {
        set({ alerts: {}, incidents: {}, runs: {}, telemetry: [] })
        void get().bootstrap()
      })
      source.onerror = () => {
        set({ connection: 'offline' })
        source?.close()
        if (!closed) retry = setTimeout(open, 2000)
      }
    }
    open()
    return () => {
      closed = true
      clearTimeout(retry)
      source?.close()
    }
  },

  applySettings: (s) => set((st) => (st.overview ? { overview: { ...st.overview, ...s } } : {})),

  upsertAlert: (a) =>
    set((s) => {
      const prev = s.alerts[a.id]
      if (prev && prev.revision > a.revision) return {}
      return { alerts: { ...s.alerts, [a.id]: a } }
    }),

  upsertRun: (r) => {
    const prev = get().runs[r.id]
    set((s) => ({ runs: { ...s.runs, [r.id]: r } }))
    if (prev?.status === 'running' && r.status === 'completed') {
      const detail = r.detected === null
        ? `${r.false_alerts} false alert${r.false_alerts === 1 ? '' : 's'} raised`
        : r.detected ? `Detected ${r.stages.filter((x) => x.detected_at !== null).length}/${r.stages.length} stages` : 'Not detected'
      get().toast({ tone: 'success', title: `${r.name} finished`, body: detail, href: '#/simulate' })
    }
  },

  toast: (t) => {
    const id = ++toastId
    set((s) => ({ toasts: [...s.toasts.slice(-3), { ...t, id }] }))
    setTimeout(() => get().dismiss(id), 6000)
  },
  dismiss: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
  setPalette: (open) => set({ paletteOpen: open }),
  setAlertQuery: (alertQuery) => set({ alertQuery }),
}))

export const sortedAlerts = (alerts: Record<string, AlertSummary>) =>
  Object.values(alerts).sort((a, b) => b.last_seen - a.last_seen)

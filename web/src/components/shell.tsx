import clsx from 'clsx'
import {
  Activity, BellRing, BrainCircuit, CornerDownLeft, FlaskConical, LayoutGrid, Menu, Pause, Play, RotateCcw,
  Search, ShieldAlert, Swords, X, type LucideIcon,
} from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { api } from '../lib/api'
import { clock, compact, THREAT_LABEL } from '../lib/format'
import { navigate, type Route } from '../lib/router'
import { sortedAlerts, useStore } from '../lib/store'
import { Button, Kbd, Segmented, SeverityDot, spring } from './ui'

const NAV: { page: Route['page']; label: string; icon: LucideIcon; href: string }[] = [
  { page: 'overview', label: 'Overview', icon: LayoutGrid, href: '#/' },
  { page: 'alerts', label: 'Alerts', icon: BellRing, href: '#/alerts' },
  { page: 'incidents', label: 'Incidents', icon: ShieldAlert, href: '#/incidents' },
  { page: 'simulate', label: 'Simulation', icon: FlaskConical, href: '#/simulate' },
  { page: 'model', label: 'Model', icon: BrainCircuit, href: '#/model' },
]

export function Logo() {
  return (
    <div className="flex items-center gap-2.5">
      <div className="grid size-7 place-items-center rounded-lg bg-ink text-white shadow-[0_1px_0_rgb(255_255_255/0.2)_inset]">
        <svg viewBox="0 0 32 32" className="size-4" aria-hidden>
          <path d="M8 10l8 13 8-13" fill="none" stroke="currentColor" strokeWidth="3.4" strokeLinecap="round" strokeLinejoin="round" />
          <circle cx="16" cy="8.5" r="2.4" fill="#8f8ff5" />
        </svg>
      </div>
      <div className="leading-tight">
        <p className="text-[13px] font-semibold tracking-[-0.01em]">Vigil</p>
        <p className="text-[11px] text-ink-3">Threat detection</p>
      </div>
    </div>
  )
}

function SidebarContent({ route, onNavigate }: { route: Route; onNavigate?: () => void }) {
  const overview = useStore((s) => s.overview)
  const connection = useStore((s) => s.connection)
  const counts: Partial<Record<Route['page'], number>> = {
    alerts: overview?.alerts_open,
    incidents: overview?.incidents_open,
  }
  return (
    <div className="flex h-full flex-col">
      <div className="px-4 pt-4 pb-5">
        <Logo />
      </div>
      <nav className="flex-1 space-y-0.5 px-2" aria-label="Main">
        {NAV.map((item) => {
          const active = route.page === item.page
          const Icon = item.icon
          const count = counts[item.page]
          return (
            <a
              key={item.page}
              href={item.href}
              onClick={onNavigate}
              aria-current={active ? 'page' : undefined}
              className={clsx(
                'relative flex h-8 items-center gap-2.5 rounded-lg px-2.5 text-[13px] transition-colors',
                active ? 'font-medium text-ink' : 'text-ink-2 hover:bg-hover hover:text-ink',
              )}
            >
              {active && (
                <motion.span
                  layoutId="nav-active"
                  className="absolute inset-0 rounded-lg bg-surface shadow-[0_1px_2px_rgb(0_0_0/0.06),0_0_0_1px_rgb(0_0_0/0.05)]"
                  transition={spring}
                />
              )}
              <Icon size={15} className="relative" strokeWidth={active ? 2.2 : 1.8} />
              <span className="relative flex-1">{item.label}</span>
              {item.page === 'simulate' && (overview?.active_runs ?? 0) > 0 && (
                <span className="relative size-1.5 animate-pulse-dot rounded-full bg-accent" />
              )}
              {!!count && <span className="tnum relative text-xs text-ink-3">{count}</span>}
            </a>
          )
        })}
      </nav>
      <div className="m-2 rounded-xl border border-line bg-surface p-3 text-xs">
        <div className="flex items-center justify-between">
          <span className="flex items-center gap-1.5 font-medium text-ink">
            <span
              className={clsx(
                'size-1.5 rounded-full',
                connection === 'live' ? (overview?.paused ? 'bg-sev-medium' : 'animate-pulse-dot bg-good') : 'bg-sev-critical',
              )}
            />
            {connection === 'live' ? (overview?.paused ? 'Paused' : 'Live') : connection === 'connecting' ? 'Connecting' : 'Offline'}
          </span>
          <span className="tnum text-ink-3">{overview ? clock(overview.now) : '--:--:--'} UTC</span>
        </div>
        <dl className="mt-2.5 grid grid-cols-2 gap-y-1 text-ink-3">
          <dt>Throughput</dt>
          <dd className="tnum text-right text-ink-2">{overview ? `${compact(Math.round(overview.events_per_second))}/s` : '—'}</dd>
          <dt>Processed</dt>
          <dd className="tnum text-right text-ink-2">{overview ? compact(overview.events_total) : '—'}</dd>
          <dt>Model</dt>
          <dd className="truncate text-right font-mono text-[11px] text-ink-2">{overview?.model_version ?? '—'}</dd>
        </dl>
      </div>
    </div>
  )
}

export function Sidebar({ route }: { route: Route }) {
  return (
    <aside className="hidden w-60 shrink-0 border-r border-line bg-canvas lg:block">
      <div className="sticky top-0 h-dvh">
        <SidebarContent route={route} />
      </div>
    </aside>
  )
}

const TITLES: Record<Route['page'], string> = {
  overview: 'Overview',
  alerts: 'Alerts',
  incidents: 'Incidents',
  simulate: 'Simulation',
  model: 'Model',
}

export function Topbar({ route }: { route: Route }) {
  const overview = useStore((s) => s.overview)
  const applySettings = useStore((s) => s.applySettings)
  const setPalette = useStore((s) => s.setPalette)
  const [menu, setMenu] = useState(false)

  const update = (patch: Parameters<typeof api.updateSettings>[0]) => {
    applySettings({ speed: overview?.speed ?? 30, ambient: overview?.ambient ?? true, paused: overview?.paused ?? false, ...patch })
    void api.updateSettings(patch)
  }

  return (
    <>
      <header className="sticky top-0 z-30 flex h-14 items-center gap-2 border-b border-line bg-canvas/80 px-4 backdrop-blur-md sm:px-6">
        <button className="-ml-1 grid size-8 place-items-center rounded-lg text-ink-2 hover:bg-hover lg:hidden" onClick={() => setMenu(true)} aria-label="Open menu">
          <Menu size={17} />
        </button>
        <div className="flex min-w-0 items-center gap-1.5 text-[13px]">
          <span className="hidden text-ink-3 sm:inline">SOC</span>
          <span className="hidden text-ink-3 sm:inline">/</span>
          <span className="truncate font-medium">{TITLES[route.page]}</span>
          {'id' in route && route.id && (
            <>
              <span className="text-ink-3">/</span>
              <span className="font-mono text-xs text-ink-2">{route.id}</span>
            </>
          )}
        </div>
        <div className="flex-1" />
        <button
          onClick={() => setPalette(true)}
          className="hidden h-8 w-56 items-center gap-2 rounded-lg border border-line bg-surface px-2.5 text-[13px] text-ink-3 shadow-card transition-colors hover:border-line-strong md:flex"
        >
          <Search size={14} />
          <span className="flex-1 text-left">Search or jump to…</span>
          <Kbd>⌘</Kbd>
          <Kbd>K</Kbd>
        </button>
        <button className="grid size-8 place-items-center rounded-lg text-ink-2 hover:bg-hover md:hidden" onClick={() => setPalette(true)} aria-label="Search">
          <Search size={16} />
        </button>
        <div className="hidden sm:block">
          <Segmented
            label="Simulation speed"
            value={overview?.speed ?? 30}
            onChange={(speed) => update({ speed })}
            options={[1, 10, 30, 60].map((v) => ({ value: v, label: `${v}×` }))}
          />
        </div>
        <Button
          variant="secondary"
          icon={overview?.paused ? Play : Pause}
          onClick={() => update({ paused: !overview?.paused })}
          aria-label={overview?.paused ? 'Resume stream' : 'Pause stream'}
        >
          <span className="hidden sm:inline">{overview?.paused ? 'Resume' : 'Pause'}</span>
        </Button>
        {route.page !== 'simulate' && (
          <Button variant="primary" icon={Swords} onClick={() => navigate('/simulate')}>
            <span className="hidden sm:inline">Simulate attack</span>
          </Button>
        )}
      </header>
      <AnimatePresence>
        {menu && (
          <>
            <motion.div
              className="fixed inset-0 z-40 bg-black/20 lg:hidden"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setMenu(false)}
            />
            <motion.aside
              className="fixed inset-y-0 left-0 z-50 w-64 border-r border-line bg-canvas shadow-pop lg:hidden"
              initial={{ x: -280 }}
              animate={{ x: 0 }}
              exit={{ x: -280 }}
              transition={spring}
            >
              <button className="absolute top-4 right-3 grid size-7 place-items-center rounded-md text-ink-3 hover:bg-hover" onClick={() => setMenu(false)} aria-label="Close menu">
                <X size={15} />
              </button>
              <SidebarContent route={route} onNavigate={() => setMenu(false)} />
            </motion.aside>
          </>
        )}
      </AnimatePresence>
    </>
  )
}

export function Drawer({ open, onClose, children, width = 560 }: { open: boolean; onClose: () => void; children: ReactNode; width?: number }) {
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])
  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div
            className="fixed inset-0 z-40 bg-[rgb(15_15_15/0.12)]"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            onClick={onClose}
          />
          <motion.aside
            role="dialog"
            aria-modal="true"
            className="fixed inset-y-2 right-2 z-50 flex max-w-[calc(100vw-16px)] flex-col overflow-hidden rounded-2xl border border-line bg-surface shadow-pop"
            style={{ width }}
            initial={{ x: 40, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 40, opacity: 0 }}
            transition={spring}
          >
            {children}
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  )
}

interface Command {
  id: string
  group: string
  label: string
  hint?: string
  icon: LucideIcon
  severity?: Parameters<typeof SeverityDot>[0]['severity']
  run: () => void
}

export function CommandPalette() {
  const open = useStore((s) => s.paletteOpen)
  const setPalette = useStore((s) => s.setPalette)
  const alerts = useStore((s) => s.alerts)
  const incidents = useStore((s) => s.incidents)
  const scenarios = useStore((s) => s.scenarios)
  const overview = useStore((s) => s.overview)
  const toast = useStore((s) => s.toast)
  const [query, setQuery] = useState('')
  const [index, setIndex] = useState(0)
  const listRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPalette(!useStore.getState().paletteOpen)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [setPalette])

  useEffect(() => {
    if (open) {
      setQuery('')
      setIndex(0)
    }
  }, [open])

  const commands = useMemo<Command[]>(() => {
    const close = (fn: () => void) => () => {
      setPalette(false)
      fn()
    }
    const nav: Command[] = NAV.map((n) => ({
      id: `nav-${n.page}`, group: 'Navigate', label: `Go to ${n.label}`, icon: n.icon, run: close(() => navigate(n.href)),
    }))
    const actions: Command[] = [
      {
        id: 'pause', group: 'Engine', label: overview?.paused ? 'Resume telemetry stream' : 'Pause telemetry stream',
        icon: overview?.paused ? Play : Pause, run: close(() => void api.updateSettings({ paused: !overview?.paused })),
      },
      {
        id: 'reset', group: 'Engine', label: 'Reset engine state', hint: 'Clears alerts, incidents and runs', icon: RotateCcw,
        run: close(() => void api.reset().then(() => toast({ tone: 'info', title: 'Engine reset' }))),
      },
      ...scenarios.map((s) => ({
        id: `sim-${s.id}`, group: 'Simulate', label: `Launch: ${s.name}`, hint: s.difficulty, icon: FlaskConical,
        run: close(() => {
          void api.launch(s.id, 1).then((r) => {
            useStore.getState().upsertRun(r)
            toast({ tone: 'info', title: 'Simulation launched', body: s.name, href: '#/simulate' })
          })
        }),
      })),
    ]
    const incs: Command[] = Object.values(incidents).map((i) => ({
      id: i.id, group: 'Incidents', label: i.title, hint: i.id, icon: ShieldAlert, severity: i.severity,
      run: close(() => navigate(`/incidents/${i.id}`)),
    }))
    const alertCmds: Command[] = sortedAlerts(alerts).slice(0, 300).map((a) => ({
      id: a.id, group: 'Alerts', label: `${THREAT_LABEL[a.threat]} · ${a.hostname ?? a.entity}`, hint: a.id,
      icon: Activity, severity: a.severity, run: close(() => navigate(`/alerts/${a.id}`)),
    }))
    return [...nav, ...actions, ...incs, ...alertCmds]
  }, [alerts, incidents, scenarios, overview?.paused, setPalette, toast])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    const list = q
      ? commands.filter((c) => `${c.label} ${c.hint ?? ''} ${c.group}`.toLowerCase().includes(q))
      : commands.filter((c) => c.group !== 'Alerts' && c.group !== 'Incidents')
    return list.slice(0, 40)
  }, [commands, query])

  useEffect(() => setIndex(0), [query])
  useEffect(() => {
    listRef.current?.querySelector(`[data-index="${index}"]`)?.scrollIntoView({ block: 'nearest' })
  }, [index])

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setIndex((i) => Math.min(filtered.length - 1, i + 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setIndex((i) => Math.max(0, i - 1))
    } else if (e.key === 'Enter') {
      filtered[index]?.run()
    } else if (e.key === 'Escape') {
      setPalette(false)
    }
  }

  let lastGroup = ''
  return (
    <AnimatePresence>
      {open && (
        <div className="fixed inset-0 z-[60] flex items-start justify-center px-4 pt-[12vh]">
          <motion.div
            className="absolute inset-0 bg-[rgb(15_15_15/0.18)]"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.12 }}
            onClick={() => setPalette(false)}
          />
          <motion.div
            role="dialog"
            aria-label="Command menu"
            className="relative w-full max-w-xl overflow-hidden rounded-2xl border border-line bg-surface shadow-pop"
            initial={{ opacity: 0, scale: 0.97, y: -6 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.98, y: -4 }}
            transition={{ duration: 0.14, ease: [0.2, 0.8, 0.2, 1] }}
          >
            <div className="flex items-center gap-2.5 border-b border-line px-4">
              <Search size={16} className="text-ink-3" />
              <input
                autoFocus
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={onKey}
                placeholder="Search alerts, incidents, actions…"
                className="h-12 flex-1 bg-transparent text-[14px] outline-none placeholder:text-ink-3"
                role="combobox"
                aria-expanded="true"
                aria-controls="palette-list"
              />
              <Kbd>esc</Kbd>
            </div>
            <div ref={listRef} id="palette-list" role="listbox" className="scroll-thin max-h-[52vh] overflow-y-auto p-1.5">
              {filtered.length === 0 && <p className="px-3 py-8 text-center text-[13px] text-ink-3">No matches</p>}
              {filtered.map((c, i) => {
                const header = c.group !== lastGroup ? c.group : null
                lastGroup = c.group
                const Icon = c.icon
                return (
                  <div key={c.id}>
                    {header && <p className="px-2.5 pt-2.5 pb-1 text-[11px] font-medium text-ink-3">{header}</p>}
                    <button
                      data-index={i}
                      role="option"
                      aria-selected={i === index}
                      onMouseMove={() => setIndex(i)}
                      onClick={c.run}
                      className={clsx(
                        'flex h-9 w-full items-center gap-2.5 rounded-lg px-2.5 text-left text-[13px]',
                        i === index ? 'bg-subtle text-ink' : 'text-ink-2',
                      )}
                    >
                      {c.severity ? <SeverityDot severity={c.severity} className="mx-[3px]" /> : <Icon size={15} className="text-ink-3" />}
                      <span className="flex-1 truncate">{c.label}</span>
                      {c.hint && <span className="shrink-0 font-mono text-[11px] text-ink-3">{c.hint}</span>}
                      {i === index && <CornerDownLeft size={13} className="text-ink-3" />}
                    </button>
                  </div>
                )
              })}
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  )
}

export function Toasts() {
  const toasts = useStore((s) => s.toasts)
  const dismiss = useStore((s) => s.dismiss)
  return (
    <div className="pointer-events-none fixed right-4 bottom-4 z-[70] flex w-[340px] max-w-[calc(100vw-32px)] flex-col gap-2" aria-live="polite">
      <AnimatePresence initial={false}>
        {toasts.map((t) => (
          <motion.div
            key={t.id}
            layout
            initial={{ opacity: 0, y: 16, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, x: 24, transition: { duration: 0.15 } }}
            transition={spring}
            className="pointer-events-auto flex gap-3 rounded-xl border border-line bg-surface p-3 shadow-pop"
          >
            <span
              className={clsx(
                'mt-1 size-2 shrink-0 rounded-full',
                t.tone === 'critical' ? 'bg-sev-critical' : t.tone === 'success' ? 'bg-good' : 'bg-accent',
              )}
            />
            <a href={t.href} onClick={() => dismiss(t.id)} className="min-w-0 flex-1">
              <p className="text-[13px] font-medium">{t.title}</p>
              {t.body && <p className="mt-0.5 line-clamp-2 text-xs text-ink-3">{t.body}</p>}
            </a>
            <button onClick={() => dismiss(t.id)} className="grid size-5 place-items-center rounded text-ink-3 hover:bg-hover" aria-label="Dismiss">
              <X size={12} />
            </button>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  )
}

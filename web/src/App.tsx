import { AnimatePresence, motion } from 'motion/react'
import { useEffect } from 'react'
import { CommandPalette, Sidebar, Toasts, Topbar } from './components/shell'
import { useRoute } from './lib/router'
import { useStore } from './lib/store'
import Alerts from './pages/Alerts'
import Incidents from './pages/Incidents'
import Model from './pages/Model'
import Overview from './pages/Overview'
import Simulate from './pages/Simulate'

export default function App() {
  const route = useRoute()
  const connect = useStore((s) => s.connect)
  const bootstrap = useStore((s) => s.bootstrap)
  const connection = useStore((s) => s.connection)
  const error = useStore((s) => s.error)

  useEffect(() => {
    void bootstrap()
    return connect()
  }, [bootstrap, connect])

  useEffect(() => {
    const titles = { overview: 'Overview', alerts: 'Alerts', incidents: 'Incidents', simulate: 'Simulation', model: 'Model' }
    document.title = `${titles[route.page]} · Vigil`
  }, [route.page])

  return (
    <div className="flex min-h-dvh">
      <Sidebar route={route} />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar route={route} />
        {connection === 'offline' && (
          <div className="border-b border-[#f3d4d4] bg-[#fdf5f5] px-6 py-2 text-[13px] text-[#8f2424]">
            Lost connection to the engine{error ? ` (${error})` : ''}. Retrying… Is the API running on port 8710?
          </div>
        )}
        <main className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-6 sm:px-6">
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={route.page}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.16, ease: [0.2, 0.8, 0.2, 1] }}
            >
              {route.page === 'overview' && <Overview />}
              {route.page === 'alerts' && <Alerts selected={route.id} />}
              {route.page === 'incidents' && <Incidents selected={route.id} />}
              {route.page === 'simulate' && <Simulate />}
              {route.page === 'model' && <Model />}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
      <CommandPalette />
      <Toasts />
    </div>
  )
}

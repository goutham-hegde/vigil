import { useSyncExternalStore } from 'react'

export type Route =
  | { page: 'overview' }
  | { page: 'alerts'; id?: string }
  | { page: 'incidents'; id?: string }
  | { page: 'simulate' }
  | { page: 'model' }

function parse(hash: string): Route {
  const [page, id] = hash.replace(/^#\/?/, '').split('/')
  switch (page) {
    case 'alerts':
      return { page, id: id || undefined }
    case 'incidents':
      return { page, id: id || undefined }
    case 'simulate':
    case 'model':
      return { page }
    default:
      return { page: 'overview' }
  }
}

const subscribe = (cb: () => void) => {
  window.addEventListener('hashchange', cb)
  return () => window.removeEventListener('hashchange', cb)
}

export function useRoute(): Route {
  const hash = useSyncExternalStore(subscribe, () => window.location.hash)
  return parse(hash)
}

export function navigate(path: string) {
  const next = path.startsWith('#') ? path : `#${path}`
  if (window.location.hash !== next) window.location.hash = next
}

import { useEffect, useState } from 'react'
import { api, type Info } from './api'
import { Spinner } from './components/ui'
import { ClientsPage } from './pages/Clients'
import { GroupsPage } from './pages/Groups'
import { ActivityPage } from './pages/Activity'
import { OverviewPage } from './pages/Overview'
import { SettingsPage } from './pages/Settings'
import { UserDetailPage } from './pages/UserDetail'
import { UsersPage } from './pages/Users'

const pages = [
  { id: 'overview', label: 'Overview' },
  { id: 'users', label: 'Users' },
  { id: 'groups', label: 'Groups' },
  { id: 'clients', label: 'Clients' },
  { id: 'activity', label: 'Activity' },
  { id: 'settings', label: 'Settings' },
] as const

type PageId = (typeof pages)[number]['id']

interface Route {
  page: PageId
  /** the segments after the page: #/users/<subject>/<tab> */
  segments: string[]
}

// hash routes: the server only serves index.html, whatever the issuer path is.
// The pages can have segments and parameters: #/users/<subject>/security,
// #/activity?user=<subject>
function currentRoute(): Route {
  const [path] = window.location.hash.replace(/^#\/?/, '').split('?')
  const [first, ...segments] = path.split('/').map((s) => decodeURIComponent(s))
  return { page: pages.find((p) => p.id === first)?.id ?? 'overview', segments }
}

export function App() {
  const [route, setRoute] = useState<Route>(currentRoute)
  const page = route.page
  const [info, setInfo] = useState<Info | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const onHash = () => setRoute(currentRoute())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  useEffect(() => {
    api.info().then(setInfo, (e: Error) => setError(e.message))
  }, [])

  useEffect(() => {
    if (info) document.title = `Administration · ${info.name}`
  }, [info])

  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-x-6 gap-y-3 px-4 py-3">
          <div className="flex min-w-0 flex-wrap items-center gap-x-6 gap-y-2">
            <a href="#/overview" className="flex items-center gap-2.5 text-lg font-semibold tracking-tight">
              <span className="brand-mark" aria-hidden="true">
                {(info?.name ?? 'm').trim().charAt(0).toUpperCase()}
              </span>
              <span>
                {info?.name ?? 'minioidc'} <span className="font-normal text-slate-500 dark:text-slate-400">admin</span>
              </span>
            </a>
            <nav className="-mx-1 flex gap-1 overflow-x-auto" aria-label="Sections">
              {pages.map((p) => (
                <a
                  key={p.id}
                  href={`#/${p.id}`}
                  aria-current={page === p.id ? 'page' : undefined}
                  className={`rounded-md px-3 py-1.5 text-sm font-medium ${
                    page === p.id
                      ? 'bg-slate-100 text-slate-900 dark:bg-slate-800 dark:text-white'
                      : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white'
                  }`}
                >
                  {p.label}
                </a>
              ))}
            </nav>
          </div>
          {info && (
            <div className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-400">
              <a className="btn-ghost" href="../profile" title="Your account">
                {info.me.name || info.me.preferred_username}
              </a>
              <a className="btn-secondary" href="../connect/endsession">
                Sign out
              </a>
            </div>
          )}
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 py-6">
        {error ? (
          <div className="card p-6 text-sm text-red-600" role="alert">
            {error}
          </div>
        ) : !info ? (
          <Spinner />
        ) : page === 'overview' ? (
          <OverviewPage info={info} />
        ) : page === 'users' && route.segments[0] ? (
          <UserDetailPage key={route.segments[0]} info={info} subject={route.segments[0]} tab={route.segments[1] ?? 'profile'} />
        ) : page === 'users' ? (
          <UsersPage key={window.location.hash} info={info} />
        ) : page === 'groups' ? (
          <GroupsPage info={info} />
        ) : page === 'clients' ? (
          <ClientsPage info={info} />
        ) : page === 'activity' ? (
          <ActivityPage key={window.location.hash} info={info} />
        ) : (
          <SettingsPage />
        )}
      </main>
    </div>
  )
}

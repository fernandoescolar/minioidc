import { useEffect, useState } from 'react'
import { api, type Info } from './api'
import { Spinner } from './components/ui'
import { ClientsPage } from './pages/Clients'
import { MaintenancePage } from './pages/Maintenance'
import { UsersPage } from './pages/Users'

const pages = [
  { id: 'users', label: 'Users' },
  { id: 'clients', label: 'Clients' },
  { id: 'maintenance', label: 'Maintenance' },
] as const

type PageId = (typeof pages)[number]['id']

// hash routes: the server only serves index.html, whatever the issuer path is
function currentPage(): PageId {
  const hash = window.location.hash.replace(/^#\/?/, '')
  return pages.find((p) => p.id === hash)?.id ?? 'users'
}

export function App() {
  const [page, setPage] = useState<PageId>(currentPage)
  const [info, setInfo] = useState<Info | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const onHash = () => setPage(currentPage())
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
            <a href="#/users" className="flex items-center gap-2.5 text-lg font-semibold tracking-tight">
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
        ) : page === 'users' ? (
          <UsersPage info={info} />
        ) : page === 'clients' ? (
          <ClientsPage info={info} />
        ) : (
          <MaintenancePage />
        )}
      </main>
    </div>
  )
}

import { useCallback, useEffect, useState } from 'react'
import { api, eventsCSVURL, type ActivityEvent, type EventQuery, type EventSummary, type Info } from '../api'
import { Badge, EmptyState, Spinner, formatDate, useAction } from '../components/ui'
import { userURL } from './userActions'

/** the names of the event types */
export const eventLabels: Record<string, string> = {
  'login.password': 'Sign in with password',
  'login.passkey': 'Sign in with passkey',
  'login.mfa': 'MFA code',
  'login.lockout': 'Blocked: too many failed attempts',
  'login.denied': 'Denied by the allowed groups',
  'login.ldap': 'LDAP bind',
  'login.password_grant': 'Password grant',
  logout: 'Sign out',
  'account.password_change': 'Password changed',
  'account.password_reset': 'Password reset with a link',
  'account.mfa_add': 'Authenticator app added',
  'account.mfa_remove': 'Authenticator app removed',
  'account.passkey_add': 'Passkey added',
  'account.passkey_remove': 'Passkey removed',
  'account.device_approve': 'Device sign in',
  'account.setup': 'Setup',
  'admin.user': 'User',
  'admin.password': 'Password',
  'admin.state': 'Account state',
  'admin.credentials': 'Sessions and credentials',
  'admin.client': 'Client',
  'admin.maintenance': 'Maintenance',
  'admin.group': 'Group',
}

const categories = [
  { value: '', label: 'All the events' },
  { value: 'login.', label: 'Sign ins' },
  { value: 'login.lockout', label: 'Blocks (brute force)' },
  { value: 'logout', label: 'Sign outs' },
  { value: 'account.', label: 'Account changes' },
  { value: 'admin.', label: 'Administration' },
]

/** the parameters of the hash: #/activity?user=<subject> */
function hashParams() {
  const [, query = ''] = window.location.hash.split('?')
  return new URLSearchParams(query)
}

/** the date inputs are local days: the filter uses the start of the day */
const dayStart = (day: string) => (day ? new Date(`${day}T00:00:00`).toISOString() : '')
const dayEnd = (day: string) => {
  if (!day) return ''
  const end = new Date(`${day}T00:00:00`)
  end.setDate(end.getDate() + 1)
  return end.toISOString()
}

/** the activity log. With user, the events of that user (in the page of the user) */
export function ActivityPage({ info, user: fixedUser }: { info: Info; user?: string }) {
  const [user, setUser] = useState(() => fixedUser ?? hashParams().get('user') ?? '')
  const [search, setSearch] = useState('')
  const [debounced, setDebounced] = useState('')
  const [type, setType] = useState(() => hashParams().get('type') ?? '')
  const [result, setResult] = useState(() => hashParams().get('result') ?? '')
  const [since, setSince] = useState('')
  const [until, setUntil] = useState('')
  const [events, setEvents] = useState<ActivityEvent[] | null>(null)
  const [next, setNext] = useState(0)
  const [summary, setSummary] = useState<EventSummary | null>(null)
  const run = useAction()

  // the back button, or a link to the activity of another user
  useEffect(() => {
    if (fixedUser) return
    const onHash = () => setUser(hashParams().get('user') ?? '')
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [fixedUser])

  useEffect(() => {
    const timer = setTimeout(() => setDebounced(search.trim()), 300)
    return () => clearTimeout(timer)
  }, [search])

  const query: EventQuery = {
    user,
    q: debounced,
    type,
    result,
    since: dayStart(since),
    until: dayEnd(until),
  }
  const queryKey = JSON.stringify(query)

  const load = useCallback(
    (before?: number) =>
      run(async () => {
        const page = await api.events({
          ...(JSON.parse(queryKey) as EventQuery),
          before,
        })
        setEvents((current) => (before ? [...(current ?? []), ...page.events] : page.events))
        setNext(page.next)
      }),
    [run, queryKey],
  )

  useEffect(() => {
    setEvents(null)
    load()
  }, [load])

  useEffect(() => {
    if (!fixedUser) run(async () => setSummary(await api.eventSummary()))
  }, [run, fixedUser])

  const userLabel = events?.find((e) => e.user_id === user)?.username ?? user
  const showIncidents = () => {
    setType('login.')
    setResult('failure')
  }

  return (
    <section className="flex flex-col gap-4">
      {summary && (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
          <Stat label="Sign ins" value={summary.logins} />
          <Stat label="Failed sign ins" value={summary.failed_logins} warn={summary.failed_logins > 0} onClick={showIncidents} />
          <Stat
            label="Blocks"
            value={summary.lockouts}
            warn={summary.lockouts > 0}
            onClick={() => {
              setType('login.lockout')
              setResult('')
            }}
          />
          <Stat label="Account changes" value={summary.account_changes} />
          <Stat label="Admin actions" value={summary.admin_actions} />
        </div>
      )}
      {summary && (
        <p className="-mt-2 text-xs text-slate-500 dark:text-slate-400">
          The last 24 hours. The events are kept for {info.event_retention_days} days.
        </p>
      )}

      <div className="flex flex-wrap items-end gap-3">
        <input
          type="search"
          className="input max-w-xs"
          placeholder="Search user, admin, client or IP…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label="Search events"
        />
        <select className="input w-auto" value={type} onChange={(e) => setType(e.target.value)} aria-label="Type of event">
          {categories.map((c) => (
            <option key={c.value} value={c.value}>
              {c.label}
            </option>
          ))}
        </select>
        <select className="input w-auto" value={result} onChange={(e) => setResult(e.target.value)} aria-label="Result">
          <option value="">Any result</option>
          <option value="success">Success</option>
          <option value="failure">Failures</option>
        </select>
        <label className="flex items-center gap-2 text-sm">
          From
          <input type="date" className="input w-auto" value={since} onChange={(e) => setSince(e.target.value)} />
        </label>
        <label className="flex items-center gap-2 text-sm">
          To
          <input type="date" className="input w-auto" value={until} onChange={(e) => setUntil(e.target.value)} />
        </label>
        <a className="btn-secondary ml-auto" href={eventsCSVURL(query)} download>
          Export CSV
        </a>
      </div>

      {user && !fixedUser && (
        <div>
          <span className="inline-flex items-center gap-2 rounded-full bg-indigo-50 py-1 pr-1 pl-3 text-sm text-indigo-800 dark:bg-indigo-950 dark:text-indigo-200">
            User: {userLabel}
            <button
              type="button"
              className="rounded-full px-1.5 hover:bg-indigo-100 dark:hover:bg-indigo-900"
              aria-label="Show all the users"
              onClick={() => {
                setUser('')
                window.history.replaceState(null, '', '#/activity')
              }}
            >
              ✕
            </button>
          </span>
        </div>
      )}

      <div className="card overflow-x-auto">
        {events === null ? (
          <Spinner />
        ) : events.length === 0 ? (
          <EmptyState>There are no events.</EmptyState>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="border-b border-slate-200 text-xs text-slate-500 uppercase dark:border-slate-800 dark:text-slate-400">
              <tr>
                <th className="px-4 py-2 font-medium">Time</th>
                <th className="px-4 py-2 font-medium">Event</th>
                <th className="px-4 py-2 font-medium">User</th>
                <th className="hidden px-4 py-2 font-medium md:table-cell">Client</th>
                <th className="hidden px-4 py-2 font-medium lg:table-cell">IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {events.map((e) => (
                <tr key={e.id} className="align-top">
                  <td className="px-4 py-2.5 whitespace-nowrap text-slate-600 dark:text-slate-400">{formatDate(e.time)}</td>
                  <td className="px-4 py-2.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge color={e.result === 'failure' ? 'red' : 'green'}>{e.result === 'failure' ? 'failed' : 'ok'}</Badge>
                      <span className="font-medium">{eventLabels[e.type] ?? e.type}</span>
                    </div>
                    {(e.detail || e.actor) && (
                      <div className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                        {e.actor && <>by {e.actor}</>}
                        {e.actor && e.detail && ' · '}
                        {e.detail}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-2.5">
                    {e.user_id ? (
                      <a className="link" href={userURL(e.user_id, 'activity')}>
                        {e.username || e.user_id}
                      </a>
                    ) : (
                      <span className="text-slate-500 dark:text-slate-400">{e.username || '—'}</span>
                    )}
                  </td>
                  <td className="hidden px-4 py-2.5 md:table-cell">{e.client_id}</td>
                  <td className="hidden px-4 py-2.5 font-mono text-xs lg:table-cell" title={e.user_agent}>
                    {e.ip}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {next > 0 && (
        <div className="flex justify-center">
          <button type="button" className="btn-secondary" onClick={() => load(next)}>
            Load more
          </button>
        </div>
      )}
    </section>
  )
}

function Stat({ label, value, warn, onClick }: { label: string; value: number; warn?: boolean; onClick?: () => void }) {
  const content = (
    <>
      <div className="text-xs text-slate-500 dark:text-slate-400">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${warn ? 'text-red-600 dark:text-red-400' : ''}`}>{value}</div>
    </>
  )

  return onClick ? (
    <button type="button" className="card p-4 text-left hover:border-indigo-300 dark:hover:border-indigo-700" onClick={onClick}>
      {content}
    </button>
  ) : (
    <div className="card p-4">{content}</div>
  )
}

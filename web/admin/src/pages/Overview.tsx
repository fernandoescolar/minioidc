import { useEffect, useState } from 'react'
import { api, type Info, type Overview } from '../api'
import { Badge, EmptyState, Spinner, formatDate, useAction } from '../components/ui'
import { eventLabels } from './Activity'
import { userURL } from './userActions'

/** the dashboard: the state of the accounts, the activity and the incidents */
export function OverviewPage({ info }: { info: Info }) {
  const [overview, setOverview] = useState<Overview | null>(null)
  const run = useAction()

  useEffect(() => {
    run(async () => setOverview(await api.overview()))
  }, [run])

  if (!overview) return <Spinner />

  const users = overview.users
  const activity = overview.activity
  return (
    <section className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold">{info.name}</h1>
        <p className="text-sm text-slate-500 dark:text-slate-400">
          Issuer <code className="font-mono">{info.issuer}</code>
        </p>
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Users" value={users?.total ?? '—'} href="#/users" />
        <Stat label="Sign ins (24 h)" value={activity.logins} href="#/activity?type=login.&result=success" />
        <Stat
          label="Failed sign ins (24 h)"
          value={activity.failed_logins}
          warn={activity.failed_logins > 0}
          href="#/activity?type=login.&result=failure"
        />
        <Stat label="Blocks (24 h)" value={activity.lockouts} warn={activity.lockouts > 0} href="#/activity?type=login.lockout" />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="card p-5">
          <h2 className="font-semibold">Accounts</h2>
          {users ? (
            <ul className="mt-3 divide-y divide-slate-100 text-sm dark:divide-slate-800">
              <Row label="Administrators" value={users.admins} href="#/users?status=admin" />
              <Row label="With two-step verification" value={users.with_mfa} total={users.total} href="#/users?status=mfa" />
              {info.passkeys_enabled && (
                <Row label="With passkeys" value={users.with_passkeys} total={users.total} href="#/users?status=passkeys" />
              )}
              <Row label="Disabled" value={users.disabled} warn href="#/users?status=disabled" />
              <Row label="Locked" value={users.locked} warn href="#/users?status=locked" />
              <Row label="Blocked by failed attempts" value={users.blocked} warn href="#/users?status=blocked" />
              <Row label="With a temporary password" value={users.temporary_password} href="#/users?status=temporary_password" />
              <Row label="Never signed in" value={users.never_signed_in} />
            </ul>
          ) : (
            <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
              The users are managed in LDAP: they cannot be counted here.
            </p>
          )}
          <div className="mt-4 flex flex-wrap gap-2 text-sm">
            <a className="btn-secondary" href="#/groups">
              {overview.groups} {overview.groups === 1 ? 'group' : 'groups'}
            </a>
            <a className="btn-secondary" href="#/clients">
              {overview.clients} {overview.clients === 1 ? 'client' : 'clients'}
            </a>
          </div>
        </div>

        <div className="card p-5">
          <div className="flex items-center justify-between gap-3">
            <h2 className="font-semibold">Recent incidents</h2>
            <a className="link text-sm" href="#/activity?result=failure">
              All
            </a>
          </div>
          {overview.incidents.length === 0 ? (
            <EmptyState>There are no failures.</EmptyState>
          ) : (
            <ul className="mt-3 divide-y divide-slate-100 text-sm dark:divide-slate-800">
              {overview.incidents.map((e) => (
                <li key={e.id} className="py-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge color="red">{eventLabels[e.type] ?? e.type}</Badge>
                    {e.user_id ? (
                      <a className="link" href={userURL(e.user_id, 'activity')}>
                        {e.username || e.user_id}
                      </a>
                    ) : (
                      <span className="text-slate-600 dark:text-slate-300">{e.username || '—'}</span>
                    )}
                    {e.client_id && <span className="text-slate-500 dark:text-slate-400">· {e.client_id}</span>}
                  </div>
                  <div className="text-xs text-slate-500 dark:text-slate-400">
                    {formatDate(e.time)}
                    {e.ip && ` · ${e.ip}`}
                    {e.detail && ` · ${e.detail}`}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </section>
  )
}

function Stat({ label, value, warn, href }: { label: string; value: number | string; warn?: boolean; href: string }) {
  return (
    <a className="card p-4 hover:border-indigo-300 dark:hover:border-indigo-700" href={href}>
      <div className="text-xs text-slate-500 dark:text-slate-400">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${warn ? 'text-red-600 dark:text-red-400' : ''}`}>{value}</div>
    </a>
  )
}

function Row({
  label,
  value,
  total,
  warn,
  href,
}: {
  label: string
  value: number
  total?: number
  warn?: boolean
  href?: string
}) {
  const content = (
    <>
      <span>{label}</span>
      <span className={`font-medium tabular-nums ${warn && value > 0 ? 'text-red-600 dark:text-red-400' : ''}`}>
        {value}
        {total !== undefined && total > 0 && (
          <span className="ml-1 text-xs font-normal text-slate-500">({Math.round((value / total) * 100)}%)</span>
        )}
      </span>
    </>
  )

  return (
    <li>
      {href ? (
        <a className="flex justify-between gap-3 py-2 hover:text-indigo-700 dark:hover:text-indigo-300" href={href}>
          {content}
        </a>
      ) : (
        <div className="flex justify-between gap-3 py-2">{content}</div>
      )}
    </li>
  )
}

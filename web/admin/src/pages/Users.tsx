import { useCallback, useEffect, useState } from 'react'
import { api, type Info, type User, type UserPage, type UserStatus } from '../api'
import { Badge, EmptyState, Menu, Modal, Spinner, formatDate, useAction } from '../components/ui'
import { UserForm } from './UserForm'
import { useUserActions, userURL } from './userActions'

const pageSize = 50

const statuses: { value: UserStatus; label: string }[] = [
  { value: '', label: 'All the users' },
  { value: 'admin', label: 'Administrators' },
  { value: 'disabled', label: 'Disabled' },
  { value: 'locked', label: 'Locked' },
  { value: 'blocked', label: 'Blocked (failed attempts)' },
  { value: 'temporary_password', label: 'Temporary password' },
  { value: 'no_mfa', label: 'Without MFA' },
  { value: 'mfa', label: 'With MFA' },
  { value: 'passkeys', label: 'With passkeys' },
]

/** the tooltip of a state: who, why and when */
export function stateTitle(state: string, by?: string, reason?: string, at?: string) {
  return `${state}${by ? ` by ${by}` : ''}${at ? ` on ${formatDate(at)}` : ''}${reason ? `: ${reason}` : ''}`
}

/** the badges of the state and the security of a user */
export function UserBadges({ user }: { user: User }) {
  return (
    <div className="flex flex-wrap gap-1">
      {user.disabled && (
        <Badge color="red" title={stateTitle('Disabled', user.disabled_by, user.disabled_reason, user.disabled_at)}>
          disabled
        </Badge>
      )}
      {user.locked && (
        <Badge color="red" title={stateTitle('Locked', user.locked_by, user.lock_reason)}>
          {user.locked_until ? `locked until ${formatDate(user.locked_until)}` : 'locked'}
        </Badge>
      )}
      {user.blocked && (
        <Badge color="amber" title="Too many failed attempts: it ends in 15 minutes">
          blocked
        </Badge>
      )}
      {user.password_change_required && <Badge color="amber">temporary password</Badge>}
      {user.has_mfa && <Badge color="green">MFA</Badge>}
      {user.passkeys > 0 && <Badge color="green">{user.passkeys === 1 ? 'passkey' : `${user.passkeys} passkeys`}</Badge>}
      {!user.has_password && <Badge color="amber">no password</Badge>}
    </div>
  )
}

export function UsersPage({ info }: { info: Info }) {
  const [page, setPage] = useState<UserPage | null>(null)
  const [search, setSearch] = useState('')
  const [query, setQuery] = useState('')
  // the dashboard links to the users of a status: #/users?status=locked
  const [status, setStatus] = useState<UserStatus>(
    () => (new URLSearchParams(window.location.hash.split('?')[1] ?? '').get('status') ?? '') as UserStatus,
  )
  const [offset, setOffset] = useState(0)
  const [creating, setCreating] = useState(false)
  const editable = !info.users_readonly
  const run = useAction()

  // the search waits until the user stops typing
  useEffect(() => {
    const timer = setTimeout(() => {
      setQuery(search.trim())
      setOffset(0)
    }, 300)
    return () => clearTimeout(timer)
  }, [search])

  const load = useCallback(
    () => run(async () => setPage(await api.users({ q: query, status, limit: pageSize, offset }))),
    [run, query, status, offset],
  )
  useEffect(() => {
    load()
  }, [load])

  const actions = useUserActions(info, load)

  if (!info.users_listable) {
    return (
      <div className="card p-6 text-sm text-slate-600 dark:text-slate-300">
        The users are managed in LDAP, so they cannot be listed here. Store the users in SQLite (<code>sqlite.use_in_users</code>)
        to manage them from this page.
      </div>
    )
  }

  const filtered = query !== '' || status !== ''
  return (
    <section>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap gap-3">
          <input
            type="search"
            className="input sm:w-72"
            placeholder="Search users or groups…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Search users"
          />
          <select
            className="input w-auto"
            value={status}
            onChange={(e) => {
              setStatus(e.target.value as UserStatus)
              setOffset(0)
            }}
            aria-label="Status"
          >
            {statuses.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </select>
        </div>
        {editable && (
          <button type="button" className="btn-primary" onClick={() => setCreating(true)}>
            New user
          </button>
        )}
      </div>

      {!editable && (
        <div className="alert-info mb-4">
          The users are defined in the configuration file: their profile and password are changed there. From here you can lock or
          disable them and manage their sessions, MFA and passkeys.
        </div>
      )}

      <div className="card overflow-x-auto">
        {page === null ? (
          <Spinner />
        ) : page.users.length === 0 ? (
          <EmptyState>{filtered ? 'No user matches the search.' : 'There are no users yet.'}</EmptyState>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="border-b border-slate-200 text-xs text-slate-500 uppercase dark:border-slate-800 dark:text-slate-400">
              <tr>
                <th className="px-4 py-2 font-medium">User</th>
                <th className="hidden px-4 py-2 font-medium md:table-cell">Email</th>
                <th className="hidden px-4 py-2 font-medium lg:table-cell">Groups</th>
                <th className="hidden px-4 py-2 font-medium sm:table-cell">Status</th>
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {page.users.map((user) => (
                <tr
                  key={user.subject}
                  className={`hover:bg-slate-50 dark:hover:bg-slate-800/50 ${user.disabled ? 'opacity-60' : ''}`}
                >
                  <td className="px-4 py-2.5">
                    <a className="font-medium hover:underline" href={userURL(user)}>
                      {user.preferred_username}
                    </a>
                    {user.name && <div className="text-xs text-slate-500 dark:text-slate-400">{user.name}</div>}
                    {user.email && <div className="text-xs text-slate-500 md:hidden dark:text-slate-400">{user.email}</div>}
                    <div className="text-xs text-slate-400 dark:text-slate-500">
                      {user.last_login_at ? `Last sign in ${formatDate(user.last_login_at)}` : 'Never signed in'}
                    </div>
                  </td>
                  <td className="hidden px-4 py-2.5 md:table-cell">
                    {user.email}
                    {user.email && !user.email_verified && (
                      <span className="ml-1.5">
                        <Badge color="amber">unverified</Badge>
                      </span>
                    )}
                  </td>
                  <td className="hidden px-4 py-2.5 lg:table-cell">
                    <div className="flex flex-wrap gap-1">
                      {user.groups.map((g) => (
                        <Badge key={g} color={g === info.admin_group ? 'indigo' : 'gray'}>
                          {g}
                        </Badge>
                      ))}
                    </div>
                  </td>
                  <td className="hidden px-4 py-2.5 sm:table-cell">
                    <UserBadges user={user} />
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex flex-wrap items-center justify-end gap-1">
                      <a className="btn-ghost" href={userURL(user)}>
                        Open
                      </a>
                      <Menu label="More" items={actions.items(user)} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {page && page.total > pageSize && (
        <div className="mt-4 flex items-center justify-between gap-3 text-sm text-slate-600 dark:text-slate-400">
          <span>
            {offset + 1}–{Math.min(offset + pageSize, page.total)} of {page.total}
          </span>
          <div className="flex gap-2">
            <button
              type="button"
              className="btn-secondary"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - pageSize))}
            >
              Previous
            </button>
            <button
              type="button"
              className="btn-secondary"
              disabled={offset + pageSize >= page.total}
              onClick={() => setOffset(offset + pageSize)}
            >
              Next
            </button>
          </div>
        </div>
      )}

      {actions.dialogs}
      {creating && (
        <Modal
          title="New user"
          onClose={() => setCreating(false)}
          wide
          footer={
            <>
              <button type="button" className="btn-secondary" onClick={() => setCreating(false)}>
                Cancel
              </button>
              <button type="submit" form="new-user" className="btn-primary">
                Create
              </button>
            </>
          }
        >
          <UserForm
            user={null}
            info={info}
            formId="new-user"
            onSaved={(user) => {
              setCreating(false)
              window.location.hash = userURL(user)
            }}
          />
        </Modal>
      )}
    </section>
  )
}

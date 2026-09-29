import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { api, type Info, type Session, type User, type UserInput } from '../api'
import { Badge, EmptyState, Field, Modal, Spinner, formatDate, useAction, useConfirm } from '../components/ui'

export function UsersPage({ info }: { info: Info }) {
  const [users, setUsers] = useState<User[] | null>(null)
  const [filter, setFilter] = useState('')
  const [editing, setEditing] = useState<User | 'new' | null>(null)
  const [sessionsOf, setSessionsOf] = useState<User | null>(null)
  const run = useAction()
  const confirm = useConfirm()

  const load = useCallback(() => run(async () => setUsers(await api.users())), [run])
  useEffect(() => {
    load()
  }, [load])

  const visible = useMemo(() => {
    const text = filter.trim().toLowerCase()
    return (users ?? []).filter((u) =>
      [u.preferred_username, u.name, u.email, ...u.groups].some((v) => v.toLowerCase().includes(text)),
    )
  }, [users, filter])

  const remove = async (user: User) => {
    const ok = await confirm({
      title: 'Delete user',
      message: (
        <>
          <strong>{user.preferred_username}</strong> will be deleted, with their sessions and MFA. The tokens of their sessions
          stop working.
        </>
      ),
      confirmLabel: 'Delete',
      danger: true,
    })
    if (ok && (await run(() => api.deleteUser(user.subject), `${user.preferred_username} deleted`))) load()
  }

  const resetMFA = async (user: User) => {
    const ok = await confirm({
      title: 'Reset MFA',
      message: `${user.preferred_username} will enroll a new authenticator app in the next login.`,
      confirmLabel: 'Reset MFA',
      danger: true,
    })
    if (ok && (await run(() => api.resetMFA(user.subject), 'MFA reset'))) load()
  }

  const unblock = async (user: User) => {
    if (await run(() => api.unblock(user.subject), `${user.preferred_username} unblocked`)) load()
  }

  if (info.users_readonly) {
    return (
      <div className="card p-6 text-sm text-slate-600 dark:text-slate-300">
        The users are managed in LDAP or in the configuration file, so they cannot be changed here. Store the users in SQLite
        (<code>sqlite.use_in_users</code>) to manage them from this page.
      </div>
    )
  }

  return (
    <section>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <input
          type="search"
          className="input max-w-xs"
          placeholder="Search users…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          aria-label="Search users"
        />
        <button type="button" className="btn-primary" onClick={() => setEditing('new')}>
          New user
        </button>
      </div>

      <div className="card overflow-x-auto">
        {users === null ? (
          <Spinner />
        ) : visible.length === 0 ? (
          <EmptyState>{users.length === 0 ? 'There are no users yet.' : 'No user matches the search.'}</EmptyState>
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
              {visible.map((user) => (
                <tr key={user.subject} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                  <td className="px-4 py-2.5">
                    <div className="font-medium">{user.preferred_username}</div>
                    {user.name && <div className="text-xs text-slate-500 dark:text-slate-400">{user.name}</div>}
                    {user.email && <div className="text-xs text-slate-500 md:hidden dark:text-slate-400">{user.email}</div>}
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
                    <div className="flex flex-wrap gap-1">
                      {user.has_mfa && <Badge color="green">MFA</Badge>}
                      {user.blocked && <Badge color="red">blocked</Badge>}
                      {!user.has_password && <Badge color="amber">no password</Badge>}
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex flex-wrap justify-end gap-1">
                      <button type="button" className="btn-ghost" onClick={() => setEditing(user)}>
                        Edit
                      </button>
                      <button type="button" className="btn-ghost" onClick={() => setSessionsOf(user)}>
                        Sessions
                      </button>
                      {user.blocked && (
                        <button type="button" className="btn-ghost" onClick={() => unblock(user)}>
                          Unblock
                        </button>
                      )}
                      {user.has_mfa && (
                        <button type="button" className="btn-ghost" onClick={() => resetMFA(user)}>
                          Reset MFA
                        </button>
                      )}
                      {user.subject !== info.me.subject && (
                        <button type="button" className="btn-ghost text-red-600 dark:text-red-400" onClick={() => remove(user)}>
                          Delete
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {editing && (
        <UserDialog
          user={editing === 'new' ? null : editing}
          info={info}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null)
            load()
          }}
        />
      )}
      {sessionsOf && <SessionsDialog user={sessionsOf} onClose={() => setSessionsOf(null)} />}
    </section>
  )
}

function UserDialog({ user, info, onClose, onSaved }: { user: User | null; info: Info; onClose: () => void; onSaved: () => void }) {
  const [form, setForm] = useState<UserInput & { groupsText: string }>({
    preferred_username: user?.preferred_username ?? '',
    email: user?.email ?? '',
    email_verified: user?.email_verified ?? false,
    name: user?.name ?? '',
    given_name: user?.given_name ?? '',
    family_name: user?.family_name ?? '',
    phone: user?.phone ?? '',
    address: user?.address ?? '',
    groups: user?.groups ?? [],
    groupsText: (user?.groups ?? []).join(', '),
    password: '',
  })
  const [saving, setSaving] = useState(false)
  const run = useAction()
  const set = <K extends keyof typeof form>(key: K, value: (typeof form)[K]) => setForm((f) => ({ ...f, [key]: value }))

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setSaving(true)
    const { groupsText, ...input } = form
    input.groups = groupsText
      .split(',')
      .map((g) => g.trim())
      .filter(Boolean)
    const ok = await run(
      () => (user ? api.updateUser(user.subject, input) : api.createUser(input)),
      user ? 'User saved' : 'User created',
    )
    setSaving(false)
    if (ok) onSaved()
  }

  const text = (key: 'preferred_username' | 'email' | 'name' | 'given_name' | 'family_name' | 'phone' | 'address', label: string, type = 'text') => (
    <Field label={label} htmlFor={key}>
      <input id={key} type={type} className="input" value={form[key]} onChange={(e) => set(key, e.target.value)} />
    </Field>
  )

  return (
    <Modal
      title={user ? `Edit ${user.preferred_username}` : 'New user'}
      onClose={onClose}
      wide
      footer={
        <>
          <button type="button" className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form="user-form" className="btn-primary" disabled={saving}>
            {saving ? 'Saving…' : 'Save'}
          </button>
        </>
      }
    >
      <form id="user-form" onSubmit={submit} className="grid gap-4 sm:grid-cols-2">
        <Field label="Username" htmlFor="preferred_username" hint="Used to log in (preferred_username claim)">
          <input
            id="preferred_username"
            className="input"
            required
            value={form.preferred_username}
            onChange={(e) => set('preferred_username', e.target.value)}
          />
        </Field>
        <Field
          label={user ? 'New password' : 'Password'}
          htmlFor="password"
          hint={user ? 'Leave it empty to keep the current password' : 'At least 8 characters'}
        >
          <input
            id="password"
            type="password"
            className="input"
            autoComplete="new-password"
            minLength={8}
            required={!user}
            value={form.password}
            onChange={(e) => set('password', e.target.value)}
          />
        </Field>
        {text('email', 'Email', 'email')}
        <div className="flex items-end pb-2">
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={form.email_verified} onChange={(e) => set('email_verified', e.target.checked)} />
            Email verified
          </label>
        </div>
        {text('name', 'Name')}
        {text('given_name', 'Given name')}
        {text('family_name', 'Family name')}
        {text('phone', 'Phone')}
        <div className="sm:col-span-2">{text('address', 'Address')}</div>
        <div className="sm:col-span-2">
          <Field label="Groups" htmlFor="groups" hint={`Separated by commas. The members of "${info.admin_group}" are administrators.`}>
            <input id="groups" className="input" value={form.groupsText} onChange={(e) => set('groupsText', e.target.value)} />
          </Field>
        </div>
      </form>
    </Modal>
  )
}

function SessionsDialog({ user, onClose }: { user: User; onClose: () => void }) {
  const [sessions, setSessions] = useState<Session[] | null>(null)
  const run = useAction()
  const confirm = useConfirm()

  const load = useCallback(() => run(async () => setSessions(await api.sessions(user.subject))), [run, user.subject])
  useEffect(() => {
    load()
  }, [load])

  const revoke = async (session: Session) => {
    if (await run(() => api.deleteSession(user.subject, session.id), 'Session closed')) load()
  }

  const revokeAll = async () => {
    const ok = await confirm({
      title: 'Close all the sessions',
      message: `${user.preferred_username} will have to log in again in every application.`,
      confirmLabel: 'Close all',
      danger: true,
    })
    if (ok && (await run(() => api.deleteSessions(user.subject), 'Sessions closed'))) load()
  }

  return (
    <Modal
      title={`Sessions of ${user.preferred_username}`}
      onClose={onClose}
      wide
      footer={
        <>
          <button type="button" className="btn-danger" onClick={revokeAll} disabled={!sessions?.length}>
            Close all
          </button>
          <button type="button" className="btn-secondary" onClick={onClose}>
            Close
          </button>
        </>
      }
    >
      {sessions === null ? (
        <Spinner />
      ) : sessions.length === 0 ? (
        <EmptyState>There are no active sessions.</EmptyState>
      ) : (
        <ul className="divide-y divide-slate-100 dark:divide-slate-800">
          {sessions.map((s) => (
            <li key={s.id} className="flex items-center justify-between gap-4 py-2.5 text-sm">
              <div>
                <div className="flex items-center gap-2">
                  Logged in {formatDate(s.auth_time)}
                  {s.current && <Badge color="indigo">this session</Badge>}
                  {s.mfa_pending ? <Badge color="amber">MFA pending</Badge> : s.auth_methods.includes('mfa') && <Badge color="green">MFA</Badge>}
                </div>
                <div className="text-xs text-slate-500 dark:text-slate-400">Expires {formatDate(s.expires_at)}</div>
              </div>
              <button type="button" className="btn-ghost text-red-600 dark:text-red-400" onClick={() => revoke(s)}>
                Close
              </button>
            </li>
          ))}
        </ul>
      )}
    </Modal>
  )
}

import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { api, type Info, type Passkey, type Session, type User } from '../api'
import { Badge, EmptyState, Menu, Spinner, formatDate, useAction, useConfirm } from '../components/ui'
import { ActivityPage } from './Activity'
import { UserBadges, stateTitle } from './Users'
import { UserForm } from './UserForm'
import { useUserActions, userURL } from './userActions'

const tabs = [
  { id: 'profile', label: 'Profile' },
  { id: 'security', label: 'Security' },
  { id: 'sessions', label: 'Sessions' },
  { id: 'activity', label: 'Activity' },
] as const

type TabId = (typeof tabs)[number]['id']

/** the page of a user: #/users/<subject>/<tab> */
export function UserDetailPage({ info, subject, tab }: { info: Info; subject: string; tab: string }) {
  const [user, setUser] = useState<User | null>(null)
  const [missing, setMissing] = useState(false)
  const [version, setVersion] = useState(0)
  const run = useAction()
  const current: TabId = tabs.find((t) => t.id === tab)?.id ?? 'profile'

  const load = useCallback(
    () =>
      run(async () => {
        try {
          setUser(await api.user(subject))
        } catch (e) {
          setMissing(true)
          throw e
        }
      }),
    [run, subject],
  )
  useEffect(() => {
    load()
  }, [load])

  // the tabs reload their data after the actions (e.g. the sessions after a lock)
  const reload = () => {
    load()
    setVersion((v) => v + 1)
  }
  const actions = useUserActions(info, reload, () => (window.location.hash = '#/users'))

  if (missing) {
    return (
      <div className="card p-6 text-sm">
        The user does not exist.{' '}
        <a className="link" href="#/users">
          Back to the users
        </a>
      </div>
    )
  }
  if (!user) return <Spinner />

  return (
    <section className="flex flex-col gap-4">
      <a className="link text-sm" href="#/users">
        ‹ Users
      </a>

      <div className="card flex flex-wrap items-center gap-4 p-5">
        <div
          className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-indigo-100 text-lg font-semibold text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300"
          aria-hidden="true"
        >
          {(user.name || user.preferred_username).charAt(0).toUpperCase()}
        </div>
        <div className="min-w-0 flex-1">
          <h1 className="flex flex-wrap items-center gap-2 text-lg font-semibold">
            {user.preferred_username}
            {user.admin && <Badge color="indigo">administrator</Badge>}
          </h1>
          <div className="text-sm text-slate-500 dark:text-slate-400">
            {[user.name, user.email].filter(Boolean).join(' · ') || 'No name or email'}
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
            <UserBadges user={user} />
            <span>{user.last_login_at ? `Last sign in ${formatDate(user.last_login_at)}` : 'Never signed in'}</span>
          </div>
        </div>
        <Menu label="Actions" items={actions.items(user)} />
      </div>

      <nav
        className="-mb-px flex gap-1 overflow-x-auto border-b border-slate-200 dark:border-slate-800"
        aria-label="User sections"
      >
        {tabs.map((t) => (
          <a
            key={t.id}
            href={userURL(user, t.id)}
            aria-current={current === t.id ? 'page' : undefined}
            className={`border-b-2 px-3 py-2 text-sm font-medium whitespace-nowrap ${
              current === t.id
                ? 'border-indigo-600 text-indigo-700 dark:border-indigo-400 dark:text-indigo-300'
                : 'border-transparent text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white'
            }`}
          >
            {t.label}
          </a>
        ))}
      </nav>

      {current === 'profile' && <ProfileTab key={version} user={user} info={info} onSaved={setUser} />}
      {current === 'security' && <SecurityTab key={version} user={user} info={info} actions={actions} onChanged={reload} />}
      {current === 'sessions' && <SessionsTab key={version} user={user} />}
      {current === 'activity' && <ActivityPage key={version} info={info} user={user.subject} />}

      {actions.dialogs}
    </section>
  )
}

function ProfileTab({ user, info, onSaved }: { user: User; info: Info; onSaved: (user: User) => void }) {
  const editable = !info.users_readonly
  return (
    <div className="card p-5">
      {!editable && (
        <p className="alert-info mb-4">This user is defined in the configuration file: its profile is changed there.</p>
      )}
      <UserForm user={user} info={info} formId="user-profile" readOnly={!editable} onSaved={onSaved} />
      {editable && (
        <div className="mt-4 flex justify-end">
          <button type="submit" form="user-profile" className="btn-primary">
            Save
          </button>
        </div>
      )}
    </div>
  )
}

function Section({
  title,
  description,
  action,
  children,
}: {
  title: string
  description?: ReactNode
  action?: ReactNode
  children?: ReactNode
}) {
  return (
    <div className="card p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="font-semibold">{title}</h2>
          {description && <div className="mt-1 text-sm text-slate-600 dark:text-slate-400">{description}</div>}
        </div>
        {action && <div className="flex flex-wrap gap-2">{action}</div>}
      </div>
      {children && <div className="mt-4">{children}</div>}
    </div>
  )
}

function SecurityTab({
  user,
  info,
  actions,
  onChanged,
}: {
  user: User
  info: Info
  actions: ReturnType<typeof useUserActions>
  onChanged: () => void
}) {
  const self = user.subject === info.me.subject

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Section
        title="Account"
        description={
          user.disabled ? (
            <span className="text-red-700 dark:text-red-400">
              {stateTitle('Disabled', user.disabled_by, user.disabled_reason, user.disabled_at)}. The user cannot sign in by any
              way.
            </span>
          ) : user.locked ? (
            <span className="text-red-700 dark:text-red-400">
              {stateTitle('Locked', user.locked_by, user.lock_reason)}
              {user.locked_until ? ` until ${formatDate(user.locked_until)}` : ' until it is unlocked'}.
            </span>
          ) : user.blocked ? (
            'Blocked for 15 minutes after too many failed attempts.'
          ) : (
            'Active: the user can sign in.'
          )
        }
        action={
          <>
            {(user.locked || user.blocked) && (
              <button type="button" className="btn-secondary" onClick={() => actions.unlock(user)}>
                Unlock
              </button>
            )}
            {!user.locked && !self && (
              <button type="button" className="btn-secondary" onClick={() => actions.openLock(user)}>
                Lock…
              </button>
            )}
            {user.disabled ? (
              <button type="button" className="btn-secondary" onClick={() => actions.enable(user)}>
                Enable
              </button>
            ) : (
              !self && (
                <button type="button" className="btn-danger" onClick={() => actions.openDisable(user)}>
                  Disable…
                </button>
              )
            )}
          </>
        }
      />

      <Section
        title="Password"
        description={
          !info.passwords_manageable
            ? 'The password is managed in the configuration file or in LDAP.'
            : user.password_change_required
              ? 'The password is temporary: the user will choose a new one in the next sign in.'
              : user.has_password
                ? 'The user has a password.'
                : 'The user has no password: they can only sign in with a passkey.'
        }
        action={
          info.passwords_manageable && (
            <button type="button" className="btn-secondary" onClick={() => actions.openPassword(user)}>
              Reset or change…
            </button>
          )
        }
      />

      <Section
        title="Two-step verification"
        description={user.has_mfa ? 'The user has an authenticator app.' : 'The user has no authenticator app.'}
        action={
          user.has_mfa && (
            <button type="button" className="btn-secondary" onClick={() => actions.resetMFA(user)}>
              Reset MFA
            </button>
          )
        }
      />

      {info.passkeys_enabled && <PasskeysSection user={user} onChanged={onChanged} />}
    </div>
  )
}

function PasskeysSection({ user, onChanged }: { user: User; onChanged: () => void }) {
  const [passkeys, setPasskeys] = useState<Passkey[] | null>(null)
  const run = useAction()
  const confirm = useConfirm()

  const load = useCallback(() => run(async () => setPasskeys(await api.passkeys(user.subject))), [run, user.subject])
  useEffect(() => {
    load()
  }, [load])

  const remove = async (passkey: Passkey) => {
    const ok = await confirm({
      title: 'Remove passkey',
      message: `${user.preferred_username} will not be able to sign in with "${passkey.name}".`,
      confirmLabel: 'Remove',
      danger: true,
    })
    if (ok && (await run(() => api.deletePasskey(user.subject, passkey.id), 'Passkey removed'))) onChanged()
  }

  const removeAll = async () => {
    const ok = await confirm({
      title: 'Remove all the passkeys',
      message: `${user.preferred_username} will have to sign in with their password (e.g. if they lost their device).`,
      confirmLabel: 'Remove all',
      danger: true,
    })
    if (ok && (await run(() => api.deletePasskeys(user.subject), 'Passkeys removed'))) onChanged()
  }

  return (
    <Section
      title="Passkeys"
      description="The user adds them in their profile. Remove them when a device is lost."
      action={
        passkeys &&
        passkeys.length > 1 && (
          <button type="button" className="btn-secondary" onClick={removeAll}>
            Remove all
          </button>
        )
      }
    >
      {passkeys === null ? (
        <Spinner />
      ) : passkeys.length === 0 ? (
        <p className="text-sm text-slate-500 dark:text-slate-400">There are no passkeys.</p>
      ) : (
        <ul className="divide-y divide-slate-100 dark:divide-slate-800">
          {passkeys.map((p) => (
            <li key={p.id} className="flex items-center justify-between gap-4 py-2.5 text-sm">
              <div className="min-w-0">
                <div className="truncate font-medium">{p.name}</div>
                <div className="text-xs text-slate-500 dark:text-slate-400">
                  Added {formatDate(p.created_at)} · {p.last_used_at ? `Last used ${formatDate(p.last_used_at)}` : 'Not used yet'}
                </div>
              </div>
              <button type="button" className="btn-ghost text-red-600 dark:text-red-400" onClick={() => remove(p)}>
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
    </Section>
  )
}

function SessionsTab({ user }: { user: User }) {
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
      message: `${user.preferred_username} will have to sign in again in every application.`,
      confirmLabel: 'Close all',
      danger: true,
    })
    if (ok && (await run(() => api.deleteSessions(user.subject), 'Sessions closed'))) load()
  }

  return (
    <Section
      title="Sessions"
      description="The open sessions of the user. Closing one signs the user out, and the tokens of its applications stop working."
      action={
        <button type="button" className="btn-danger" onClick={revokeAll} disabled={!sessions?.length}>
          Close all
        </button>
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
                <div className="flex flex-wrap items-center gap-2">
                  Signed in {formatDate(s.auth_time)}
                  {s.current && <Badge color="indigo">this session</Badge>}
                  {s.auth_methods.includes('hwk') && <Badge color="green">passkey</Badge>}
                  {s.mfa_pending ? (
                    <Badge color="amber">MFA pending</Badge>
                  ) : (
                    s.auth_methods.includes('mfa') && <Badge color="green">MFA</Badge>
                  )}
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
    </Section>
  )
}

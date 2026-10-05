import { useState, type FormEvent, type ReactNode } from 'react'
import { api, type User } from '../api'
import { CopyField, Field, Modal, formatDate, useAction } from '../components/ui'

type PasswordMode = 'link' | 'temporary' | 'set'

const passwordModes: { value: PasswordMode; label: string; description: string }[] = [
  {
    value: 'link',
    label: 'Reset link',
    description: 'A link to choose a new password, valid for 24 hours and once. You never know the password.',
  },
  {
    value: 'temporary',
    label: 'Temporary password',
    description: 'A random password that the user must change in the next sign in.',
  },
  { value: 'set', label: 'Set a password', description: 'You choose the new password.' },
]

/** resets or changes the password of a user */
export function PasswordDialog({ user, onClose, onChanged }: { user: User; onClose: () => void; onChanged: () => void }) {
  const [mode, setMode] = useState<PasswordMode>('link')
  const [password, setPassword] = useState('')
  const [requireChange, setRequireChange] = useState(true)
  const [result, setResult] = useState<ReactNode>(null)
  const [busy, setBusy] = useState(false)
  const run = useAction()

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    await run(async () => {
      if (mode === 'link') {
        const link = await api.resetLink(user.subject)
        setResult(
          <>
            <p className="mb-3 text-sm text-slate-600 dark:text-slate-300">
              Give this link to <strong>{user.preferred_username}</strong>. It works once, until {formatDate(link.expires_at)}. A new link
              replaces it.
            </p>
            <CopyField value={link.url} label="Reset link" />
          </>,
        )
      } else if (mode === 'temporary') {
        const temporary = await api.temporaryPassword(user.subject)
        setResult(
          <>
            <p className="mb-3 text-sm text-amber-700 dark:text-amber-400">
              Copy it now: it will not be shown again. {user.preferred_username} will choose a new password in the next sign in, and their
              sessions have been closed.
            </p>
            <CopyField value={temporary.password} label="Temporary password" />
          </>,
        )
      } else {
        await api.setPassword(user.subject, password, requireChange)
        setResult(
          <p className="text-sm text-slate-600 dark:text-slate-300">
            The password has been changed and the sessions of {user.preferred_username} have been closed.
            {requireChange && ' They will choose a new password in the next sign in.'}
          </p>,
        )
      }
      onChanged()
    })
    setBusy(false)
  }

  if (result) {
    return (
      <Modal
        title={`Password of ${user.preferred_username}`}
        onClose={onClose}
        footer={
          <button type="button" className="btn-primary" onClick={onClose}>
            Done
          </button>
        }
      >
        {result}
      </Modal>
    )
  }

  return (
    <Modal
      title={`Password of ${user.preferred_username}`}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form="password-form" className="btn-primary" disabled={busy}>
            {mode === 'link' ? 'Create link' : mode === 'temporary' ? 'Generate password' : 'Change password'}
          </button>
        </>
      }
    >
      <form id="password-form" onSubmit={submit} className="flex flex-col gap-4">
        <fieldset className="flex flex-col gap-2">
          <legend className="label">How</legend>
          {passwordModes.map((m) => (
            <label
              key={m.value}
              className={`flex cursor-pointer gap-3 rounded-lg border p-3 text-sm ${
                mode === m.value ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-950/40' : 'border-slate-200 dark:border-slate-700'
              }`}
            >
              <input type="radio" name="mode" className="mt-0.5" checked={mode === m.value} onChange={() => setMode(m.value)} />
              <span>
                <span className="font-medium">{m.label}</span>
                <span className="block text-xs text-slate-500 dark:text-slate-400">{m.description}</span>
              </span>
            </label>
          ))}
        </fieldset>

        {mode === 'set' && (
          <>
            <Field label="New password" htmlFor="new-password" hint="At least 8 characters">
              <input
                id="new-password"
                type="password"
                className="input"
                autoComplete="new-password"
                minLength={8}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </Field>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={requireChange} onChange={(e) => setRequireChange(e.target.checked)} />
              The user must change it in the next sign in
            </label>
          </>
        )}
      </form>
    </Modal>
  )
}

const lockDurations = [
  { value: '1h', label: '1 hour', hours: 1 },
  { value: '24h', label: '24 hours', hours: 24 },
  { value: '7d', label: '7 days', hours: 24 * 7 },
  { value: 'date', label: 'Until a date', hours: 0 },
  { value: 'forever', label: 'Until it is unlocked', hours: 0 },
] as const

/** locks an account for a while: it cannot sign in, and its sessions are closed */
export function LockDialog({ user, onClose, onChanged }: { user: User; onClose: () => void; onChanged: () => void }) {
  const [duration, setDuration] = useState<(typeof lockDurations)[number]['value']>('24h')
  const [date, setDate] = useState('')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const run = useAction()

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    const option = lockDurations.find((d) => d.value === duration)!
    let until: string | null = null
    if (option.hours > 0) until = new Date(Date.now() + option.hours * 3600_000).toISOString()
    if (duration === 'date') until = new Date(date).toISOString()

    setBusy(true)
    const ok = await run(() => api.lock(user.subject, until, reason), `${user.preferred_username} locked`)
    setBusy(false)
    if (ok) onChanged()
  }

  return (
    <Modal
      title={`Lock ${user.preferred_username}`}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form="lock-form" className="btn-danger" disabled={busy}>
            Lock
          </button>
        </>
      }
    >
      <form id="lock-form" onSubmit={submit} className="flex flex-col gap-4">
        <p className="text-sm text-slate-600 dark:text-slate-300">
          The user cannot sign in until the end of the lock, and their sessions are closed now. Use it for a temporary suspension; to
          remove the access, disable the account.
        </p>
        <Field label="Duration" htmlFor="lock-duration">
          <select id="lock-duration" className="input" value={duration} onChange={(e) => setDuration(e.target.value as typeof duration)}>
            {lockDurations.map((d) => (
              <option key={d.value} value={d.value}>
                {d.label}
              </option>
            ))}
          </select>
        </Field>
        {duration === 'date' && (
          <Field label="Until" htmlFor="lock-until">
            <input id="lock-until" type="datetime-local" className="input" required value={date} onChange={(e) => setDate(e.target.value)} />
          </Field>
        )}
        <Field label="Reason" htmlFor="lock-reason" hint="Optional. Only the administrators see it.">
          <input id="lock-reason" className="input" maxLength={256} value={reason} onChange={(e) => setReason(e.target.value)} />
        </Field>
      </form>
    </Modal>
  )
}

/** disables an account until an administrator enables it */
export function DisableDialog({ user, onClose, onChanged }: { user: User; onClose: () => void; onChanged: () => void }) {
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const run = useAction()

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    const ok = await run(() => api.disable(user.subject, reason), `${user.preferred_username} disabled`)
    setBusy(false)
    if (ok) onChanged()
  }

  return (
    <Modal
      title={`Disable ${user.preferred_username}`}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form="disable-form" className="btn-danger" disabled={busy}>
            Disable
          </button>
        </>
      }
    >
      <form id="disable-form" onSubmit={submit} className="flex flex-col gap-4">
        <p className="text-sm text-slate-600 dark:text-slate-300">
          The user cannot sign in by any way (web, passkeys, LDAP, tokens) until an administrator enables the account again. Their
          sessions are closed now and their tokens stop working. The account and its data are kept.
        </p>
        <Field label="Reason" htmlFor="disable-reason" hint="Optional. Only the administrators see it.">
          <input id="disable-reason" className="input" maxLength={256} value={reason} onChange={(e) => setReason(e.target.value)} />
        </Field>
      </form>
    </Modal>
  )
}

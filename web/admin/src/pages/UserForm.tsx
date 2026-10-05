import { useState, type FormEvent } from 'react'
import { api, type Info, type User, type UserInput } from '../api'
import { Field, GroupPicker, useAction } from '../components/ui'
import { useGroupNames } from './Groups'

type TextField = 'preferred_username' | 'email' | 'name' | 'given_name' | 'family_name' | 'phone' | 'address'

/**
 * The profile of a user: the form of a new user (with its password) and of
 * the profile tab of a user. readOnly shows it without editing.
 */
export function UserForm({
  user,
  info,
  formId,
  readOnly,
  onSaved,
}: {
  user: User | null
  info: Info
  formId: string
  readOnly?: boolean
  onSaved: (user: User) => void
}) {
  const groupNames = useGroupNames()
  const [form, setForm] = useState<UserInput>({
    preferred_username: user?.preferred_username ?? '',
    email: user?.email ?? '',
    email_verified: user?.email_verified ?? false,
    name: user?.name ?? '',
    given_name: user?.given_name ?? '',
    family_name: user?.family_name ?? '',
    phone: user?.phone ?? '',
    address: user?.address ?? '',
    groups: user?.groups ?? [],
    password: '',
  })
  const run = useAction()
  const set = <K extends keyof UserInput>(key: K, value: UserInput[K]) => setForm((f) => ({ ...f, [key]: value }))

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    let saved: User | undefined
    const ok = await run(
      async () => {
        saved = user ? await api.updateUser(user.subject, form) : await api.createUser(form)
      },
      user ? 'User saved' : 'User created',
    )
    if (ok && saved) onSaved(saved)
  }

  const text = (key: TextField, label: string, type = 'text', hint?: string) => (
    <Field label={label} htmlFor={`${formId}-${key}`} hint={hint}>
      <input
        id={`${formId}-${key}`}
        type={type}
        className="input"
        required={key === 'preferred_username'}
        disabled={readOnly}
        value={form[key]}
        onChange={(e) => set(key, e.target.value)}
      />
    </Field>
  )

  return (
    <form id={formId} onSubmit={submit} className="grid gap-4 sm:grid-cols-2">
      {text('preferred_username', 'Username', 'text', 'Used to sign in (preferred_username claim)')}
      {user ? (
        <div className="flex items-end pb-2 text-xs text-slate-500 dark:text-slate-400">The password is changed in Security.</div>
      ) : (
        <Field label="Password" htmlFor={`${formId}-password`} hint="At least 8 characters">
          <input
            id={`${formId}-password`}
            type="password"
            className="input"
            autoComplete="new-password"
            minLength={8}
            required
            value={form.password}
            onChange={(e) => set('password', e.target.value)}
          />
        </Field>
      )}
      {text('email', 'Email', 'email')}
      <div className="flex items-end pb-2">
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            disabled={readOnly}
            checked={form.email_verified}
            onChange={(e) => set('email_verified', e.target.checked)}
          />
          Email verified
        </label>
      </div>
      {text('name', 'Name')}
      {text('given_name', 'Given name')}
      {text('family_name', 'Family name')}
      {text('phone', 'Phone')}
      <div className="sm:col-span-2">{text('address', 'Address')}</div>
      <div className="sm:col-span-2">
        <Field
          label="Groups"
          htmlFor={`${formId}-groups`}
          hint={`Choose a group or write a new one. The members of "${info.admin_group}" are administrators.`}
        >
          {readOnly ? (
            <div className="text-sm">{form.groups.join(', ') || '—'}</div>
          ) : (
            <GroupPicker
              id={`${formId}-groups`}
              value={form.groups}
              onChange={(groups) => set('groups', groups)}
              suggestions={groupNames}
            />
          )}
        </Field>
      </div>
    </form>
  )
}

import { useState, type ReactNode } from 'react'
import { api, type Info, type User } from '../api'
import { useAction, useConfirm, type MenuItem } from '../components/ui'
import { DisableDialog, LockDialog, PasswordDialog } from './AccountDialogs'

/** the hash of the page of a user (and its tab) */
export const userURL = (user: User | string, tab?: string) =>
  `#/users/${encodeURIComponent(typeof user === 'string' ? user : user.subject)}${tab ? `/${tab}` : ''}`

/**
 * The actions on an account, shared by the list of users and the page of a
 * user: the menu items and the dialogs they open. onChanged reloads the user.
 * onDeleted is called after deleting the user.
 */
export function useUserActions(info: Info, onChanged: () => void, onDeleted: () => void = onChanged) {
  const [dialog, setDialog] = useState<{ kind: 'password' | 'lock' | 'disable'; user: User } | null>(null)
  const run = useAction()
  const confirm = useConfirm()
  const editable = !info.users_readonly
  const close = () => setDialog(null)
  const changed = () => {
    close()
    onChanged()
  }

  const remove = async (user: User) => {
    const ok = await confirm({
      title: 'Delete user',
      message: (
        <>
          <strong>{user.preferred_username}</strong> will be deleted, with their sessions, MFA and passkeys. The tokens of their
          sessions stop working.
        </>
      ),
      confirmLabel: 'Delete',
      danger: true,
    })
    if (ok && (await run(() => api.deleteUser(user.subject), `${user.preferred_username} deleted`))) onDeleted()
  }

  const resetMFA = async (user: User) => {
    const ok = await confirm({
      title: 'Reset MFA',
      message: `${user.preferred_username} will enroll a new authenticator app in the next login.`,
      confirmLabel: 'Reset MFA',
      danger: true,
    })
    if (ok && (await run(() => api.resetMFA(user.subject), 'MFA reset'))) onChanged()
  }

  const unlock = async (user: User) => {
    if (await run(() => api.unblock(user.subject), `${user.preferred_username} unlocked`)) onChanged()
  }

  const enable = async (user: User) => {
    if (await run(() => api.enable(user.subject), `${user.preferred_username} enabled`)) onChanged()
  }

  const self = (user: User) => user.subject === info.me.subject

  const items = (user: User): MenuItem[] => [
    { label: 'Password…', onSelect: () => setDialog({ kind: 'password', user }), hidden: !info.passwords_manageable },
    { label: 'Reset MFA', onSelect: () => resetMFA(user), hidden: !user.has_mfa },
    { label: 'Unlock', onSelect: () => unlock(user), hidden: !user.locked && !user.blocked },
    { label: 'Lock…', onSelect: () => setDialog({ kind: 'lock', user }), hidden: user.locked || self(user) },
    { label: 'Enable', onSelect: () => enable(user), hidden: !user.disabled },
    {
      label: 'Disable…',
      onSelect: () => setDialog({ kind: 'disable', user }),
      danger: true,
      hidden: user.disabled || self(user),
    },
    { label: 'Delete', onSelect: () => remove(user), danger: true, hidden: !editable || self(user) },
  ]

  let dialogs: ReactNode = null
  if (dialog?.kind === 'password') dialogs = <PasswordDialog user={dialog.user} onClose={close} onChanged={onChanged} />
  if (dialog?.kind === 'lock') dialogs = <LockDialog user={dialog.user} onClose={close} onChanged={changed} />
  if (dialog?.kind === 'disable') dialogs = <DisableDialog user={dialog.user} onClose={close} onChanged={changed} />

  return {
    items,
    dialogs,
    resetMFA,
    unlock,
    enable,
    openPassword: (user: User) => setDialog({ kind: 'password', user }),
    openLock: (user: User) => setDialog({ kind: 'lock', user }),
    openDisable: (user: User) => setDialog({ kind: 'disable', user }),
    remove,
  }
}

import type { ReactNode } from 'react'
import { api } from '../api'
import { useAction, useConfirm } from '../components/ui'

export function MaintenancePage() {
  const run = useAction()
  const confirm = useConfirm()

  const purge = () => run(api.purgeExpired, 'Expired data purged')

  const logoutAll = async () => {
    const ok = await confirm({
      title: 'Sign out all the users',
      message: 'All the sessions are closed, including yours. The users will have to sign in again in every application.',
      confirmLabel: 'Sign out everyone',
      danger: true,
    })
    if (ok && (await run(api.logoutAll))) {
      window.location.reload()
    }
  }

  return (
    <section className="grid gap-4 md:grid-cols-2">
      <Task
        title="Purge expired data"
        description="Deletes the expired sessions, codes, refresh tokens, device codes, login blocks and client assertions. It also runs every hour."
        action={
          <button type="button" className="btn-primary" onClick={purge}>
            Purge now
          </button>
        }
      />
      <Task
        title="Sign out all the users"
        description="Closes every session. The access tokens stop working immediately and the refresh tokens cannot be used any more."
        action={
          <button type="button" className="btn-danger" onClick={logoutAll}>
            Sign out everyone
          </button>
        }
      />
    </section>
  )
}

function Task({ title, description, action }: { title: string; description: string; action: ReactNode }) {
  return (
    <div className="card flex flex-col gap-3 p-5">
      <h2 className="font-semibold">{title}</h2>
      <p className="flex-1 text-sm text-slate-600 dark:text-slate-300">{description}</p>
      <div>{action}</div>
    </div>
  )
}

import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { api, type Group, type Info, type User } from '../api'
import { Badge, EmptyState, Field, Modal, Spinner, useAction, useConfirm } from '../components/ui'

/** the names of the groups, for the suggestions of the group pickers */
export function useGroupNames() {
  const [names, setNames] = useState<string[]>([])
  useEffect(() => {
    api.groups().then(
      (groups) => setNames(groups.map((g) => g.name)),
      () => setNames([]),
    )
  }, [])
  return names
}

export function GroupsPage({ info }: { info: Info }) {
  const [groups, setGroups] = useState<Group[] | null>(null)
  const [filter, setFilter] = useState('')
  const [editing, setEditing] = useState<Group | 'new' | null>(null)
  const [membersOf, setMembersOf] = useState<Group | null>(null)
  const run = useAction()
  const confirm = useConfirm()
  const manageable = info.groups_manageable

  const load = useCallback(() => run(async () => setGroups(await api.groups())), [run])
  useEffect(() => {
    load()
  }, [load])

  const visible = useMemo(() => {
    const text = filter.trim().toLowerCase()
    return (groups ?? []).filter((g) => g.name.toLowerCase().includes(text) || g.description.toLowerCase().includes(text))
  }, [groups, filter])

  const remove = async (group: Group) => {
    const ok = await confirm({
      title: 'Delete group',
      message: (
        <>
          <strong>{group.name}</strong> will be deleted
          {group.members > 0 && (
            <>
              {' '}
              and removed from its {group.members} {group.members === 1 ? 'member' : 'members'}
            </>
          )}
          .
        </>
      ),
      confirmLabel: 'Delete',
      danger: true,
    })
    if (ok && (await run(() => api.deleteGroup(group.name), `${group.name} deleted`))) load()
  }

  if (!info.users_listable) {
    return (
      <div className="card p-6 text-sm text-slate-600 dark:text-slate-300">
        The users and their groups are managed in LDAP (<code>ldap.attributes.groups</code>). You can still restrict the clients
        to some groups in their allowed groups.
      </div>
    )
  }

  return (
    <section>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <input
          type="search"
          className="input max-w-xs"
          placeholder="Search groups…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          aria-label="Search groups"
        />
        {manageable && (
          <button type="button" className="btn-primary" onClick={() => setEditing('new')}>
            New group
          </button>
        )}
      </div>

      {!manageable && (
        <div className="alert-info mb-4">
          The users are defined in the configuration file: their groups are changed there (<code>users[].groups</code>).
        </div>
      )}

      <div className="card overflow-x-auto">
        {groups === null ? (
          <Spinner />
        ) : visible.length === 0 ? (
          <EmptyState>{groups.length === 0 ? 'There are no groups yet.' : 'No group matches the search.'}</EmptyState>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="border-b border-slate-200 text-xs text-slate-500 uppercase dark:border-slate-800 dark:text-slate-400">
              <tr>
                <th className="px-4 py-2 font-medium">Group</th>
                <th className="px-4 py-2 font-medium">Members</th>
                <th className="hidden px-4 py-2 font-medium md:table-cell">Clients</th>
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {visible.map((group) => (
                <tr key={group.name} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-2 font-medium">
                      {group.name}
                      {group.admin && (
                        <Badge color="indigo" title="The members are administrators">
                          administrators
                        </Badge>
                      )}
                    </div>
                    {group.description && <div className="text-xs text-slate-500 dark:text-slate-400">{group.description}</div>}
                  </td>
                  <td className="px-4 py-2.5">
                    <button type="button" className="link" onClick={() => setMembersOf(group)}>
                      {group.members} {group.members === 1 ? 'member' : 'members'}
                    </button>
                  </td>
                  <td className="hidden px-4 py-2.5 md:table-cell">
                    <div className="flex flex-wrap gap-1">
                      {group.clients.map((c) => (
                        <Badge key={c} title="Only the members of its allowed groups can use this client">
                          {c}
                        </Badge>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex flex-wrap justify-end gap-1">
                      {manageable && (
                        <button type="button" className="btn-ghost" onClick={() => setEditing(group)}>
                          Edit
                        </button>
                      )}
                      {manageable && !group.admin && (
                        <button
                          type="button"
                          className="btn-ghost text-red-600 disabled:opacity-40 dark:text-red-400"
                          onClick={() => remove(group)}
                          disabled={group.clients.length > 0}
                          title={group.clients.length > 0 ? 'Remove it from the allowed groups of its clients first' : undefined}
                        >
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
        <GroupDialog
          group={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null)
            load()
          }}
        />
      )}
      {membersOf && (
        <MembersDialog
          group={membersOf}
          info={info}
          onClose={() => {
            setMembersOf(null)
            load()
          }}
        />
      )}
    </section>
  )
}

function GroupDialog({ group, onClose, onSaved }: { group: Group | null; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState(group?.name ?? '')
  const [description, setDescription] = useState(group?.description ?? '')
  const [saving, setSaving] = useState(false)
  const run = useAction()

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setSaving(true)
    const ok = await run(
      () => (group ? api.updateGroup(group.name, name.trim(), description) : api.createGroup(name.trim(), description)),
      group ? 'Group saved' : 'Group created',
    )
    setSaving(false)
    if (ok) onSaved()
  }

  const renamed = group !== null && name.trim() !== group.name
  return (
    <Modal
      title={group ? `Edit ${group.name}` : 'New group'}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form="group-form" className="btn-primary" disabled={saving}>
            {saving ? 'Saving…' : 'Save'}
          </button>
        </>
      }
    >
      <form id="group-form" onSubmit={submit} className="flex flex-col gap-4">
        <Field
          label="Name"
          htmlFor="group-name"
          hint={
            group?.admin
              ? 'The name of the admin group is admin.group in the configuration.'
              : 'It is the value of the groups claim.'
          }
        >
          <input
            id="group-name"
            className="input"
            required
            maxLength={64}
            disabled={group?.admin}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </Field>
        {renamed && (
          <div className="alert-warning">
            The group is renamed in its members and in the allowed groups of its clients. The applications that check the old name
            in the groups claim will stop recognizing it.
          </div>
        )}
        <Field label="Description" htmlFor="group-description" hint="Optional">
          <input id="group-description" className="input" value={description} onChange={(e) => setDescription(e.target.value)} />
        </Field>
      </form>
    </Modal>
  )
}

function MembersDialog({ group, info, onClose }: { group: Group; info: Info; onClose: () => void }) {
  const [members, setMembers] = useState<User[] | null>(null)
  const [users, setUsers] = useState<User[]>([])
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<string[]>([])
  const run = useAction()
  const manageable = info.groups_manageable

  const load = useCallback(
    () =>
      run(async () => {
        const [m, u] = await Promise.all([api.groupMembers(group.name), manageable ? api.users({ limit: 500 }).then((page) => page.users) : Promise.resolve([])])
        setMembers(m)
        setUsers(u)
      }),
    [run, group.name, manageable],
  )
  useEffect(() => {
    load()
  }, [load])

  const candidates = useMemo(() => {
    const ids = new Set((members ?? []).map((m) => m.subject))
    const text = search.trim().toLowerCase()
    return users.filter(
      (u) =>
        !ids.has(u.subject) &&
        (text === '' || [u.preferred_username, u.name, u.email].some((v) => v.toLowerCase().includes(text))),
    )
  }, [users, members, search])

  const add = async () => {
    if (await run(() => api.addGroupMembers(group.name, selected), `${selected.length} added to ${group.name}`)) {
      setSelected([])
      setSearch('')
      load()
    }
  }

  const remove = async (user: User) => {
    if (await run(() => api.removeGroupMember(group.name, user.subject), `${user.preferred_username} removed`)) load()
  }

  return (
    <Modal
      title={`Members of ${group.name}`}
      onClose={onClose}
      wide
      footer={
        <button type="button" className="btn-secondary" onClick={onClose}>
          Close
        </button>
      }
    >
      <div className="grid gap-6 md:grid-cols-2">
        <div>
          <h3 className="mb-2 text-sm font-semibold">Members</h3>
          {members === null ? (
            <Spinner />
          ) : members.length === 0 ? (
            <EmptyState>There are no members.</EmptyState>
          ) : (
            <ul className="divide-y divide-slate-100 dark:divide-slate-800">
              {members.map((m) => (
                <li key={m.subject} className="flex items-center justify-between gap-3 py-2 text-sm">
                  <div className="min-w-0">
                    <div className="truncate font-medium">{m.preferred_username}</div>
                    {m.name && <div className="truncate text-xs text-slate-500 dark:text-slate-400">{m.name}</div>}
                  </div>
                  {manageable && !(group.admin && m.subject === info.me.subject) && (
                    <button type="button" className="btn-ghost text-red-600 dark:text-red-400" onClick={() => remove(m)}>
                      Remove
                    </button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>

        {manageable && (
          <div>
            <h3 className="mb-2 text-sm font-semibold">Add members</h3>
            {group.admin && (
              <p className="alert-warning mb-3">
                The members of this group are administrators: they can manage the whole server.
              </p>
            )}
            <input
              type="search"
              className="input mb-2"
              placeholder="Search users…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              aria-label="Search users to add"
            />
            <div className="max-h-64 overflow-y-auto rounded-lg border border-slate-200 dark:border-slate-700">
              {candidates.length === 0 ? (
                <EmptyState>No users to add.</EmptyState>
              ) : (
                candidates.map((u) => (
                  <label
                    key={u.subject}
                    className="flex cursor-pointer items-center gap-3 px-3 py-2 text-sm hover:bg-slate-50 dark:hover:bg-slate-800/50"
                  >
                    <input
                      type="checkbox"
                      checked={selected.includes(u.subject)}
                      onChange={(e) =>
                        setSelected((current) =>
                          e.target.checked ? [...current, u.subject] : current.filter((s) => s !== u.subject),
                        )
                      }
                    />
                    <span className="min-w-0">
                      <span className="block truncate font-medium">{u.preferred_username}</span>
                      {u.name && <span className="block truncate text-xs text-slate-500 dark:text-slate-400">{u.name}</span>}
                    </span>
                  </label>
                ))
              )}
            </div>
            <button type="button" className="btn-primary mt-3" disabled={selected.length === 0} onClick={add}>
              Add {selected.length > 0 ? selected.length : ''} {selected.length === 1 ? 'member' : 'members'}
            </button>
          </div>
        )}
      </div>
    </Modal>
  )
}

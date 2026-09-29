import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { api, authMethods, grantTypes, usesSecret, type AuthMethod, type Client, type Info } from '../api'
import { Badge, EmptyState, Field, Modal, SecretDialog, Spinner, lines, useAction, useConfirm } from '../components/ui'

const PEM = /-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g

export function ClientsPage({ info }: { info: Info }) {
  const [clients, setClients] = useState<Client[] | null>(null)
  const [filter, setFilter] = useState('')
  const [editing, setEditing] = useState<Client | 'new' | null>(null)
  const [secret, setSecret] = useState<{ clientId: string; secret: string } | null>(null)
  const run = useAction()
  const confirm = useConfirm()

  const load = useCallback(() => run(async () => setClients(await api.clients())), [run])
  useEffect(() => {
    load()
  }, [load])

  const visible = useMemo(() => {
    const text = filter.trim().toLowerCase()
    return (clients ?? []).filter((c) => [c.id, ...c.redirect_uris].some((v) => v.toLowerCase().includes(text)))
  }, [clients, filter])

  const saved = (client: Client) => {
    setEditing(null)
    if (client.secret) setSecret({ clientId: client.id, secret: client.secret })
    load()
  }

  const rotate = async (client: Client) => {
    const ok = await confirm({
      title: 'Rotate secret',
      message: `A new secret is generated for ${client.id}. The current one stops working immediately.`,
      confirmLabel: 'Rotate',
      danger: true,
    })
    if (!ok) return
    let rotated: Client | undefined
    if (await run(async () => (rotated = await api.rotateSecret(client.id))) && rotated?.secret) {
      setSecret({ clientId: client.id, secret: rotated.secret })
    }
  }

  const revokeTokens = async (client: Client) => {
    const ok = await confirm({
      title: 'Revoke tokens',
      message: (
        <>
          The refresh tokens and pending codes of <strong>{client.id}</strong> are revoked. The access tokens already issued
          are valid until they expire.
        </>
      ),
      confirmLabel: 'Revoke',
      danger: true,
    })
    if (ok) await run(() => api.revokeClientTokens(client.id), 'Tokens revoked')
  }

  const remove = async (client: Client) => {
    const ok = await confirm({
      title: 'Delete client',
      message: (
        <>
          <strong>{client.id}</strong> and its tokens will be deleted. If it is in the configuration file, it will be added again in
          the next start.
        </>
      ),
      confirmLabel: 'Delete',
      danger: true,
    })
    if (ok && (await run(() => api.deleteClient(client.id), `${client.id} deleted`))) load()
  }

  return (
    <section>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <input
          type="search"
          className="input max-w-xs"
          placeholder="Search clients…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          aria-label="Search clients"
        />
        <button type="button" className="btn-primary" onClick={() => setEditing('new')}>
          New client
        </button>
      </div>

      <div className="card overflow-x-auto">
        {clients === null ? (
          <Spinner />
        ) : visible.length === 0 ? (
          <EmptyState>{clients.length === 0 ? 'There are no clients yet.' : 'No client matches the search.'}</EmptyState>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="border-b border-slate-200 text-xs text-slate-500 uppercase dark:border-slate-800 dark:text-slate-400">
              <tr>
                <th className="px-4 py-2 font-medium">Client</th>
                <th className="hidden px-4 py-2 font-medium sm:table-cell">Authentication</th>
                <th className="hidden px-4 py-2 font-medium xl:table-cell">Redirect URIs</th>
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {visible.map((client) => (
                <tr key={client.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                  <td className="px-4 py-2.5 font-medium">{client.id}</td>
                  <td className="hidden px-4 py-2.5 sm:table-cell">
                    <Badge color={client.token_endpoint_auth_method === 'none' ? 'amber' : 'gray'}>
                      {client.token_endpoint_auth_method || 'client_secret_basic/post'}
                    </Badge>
                  </td>
                  <td className="hidden px-4 py-2.5 text-slate-600 xl:table-cell dark:text-slate-300">
                    {client.redirect_uris.length === 0 ? (
                      <span className="text-slate-400">none (resource server)</span>
                    ) : (
                      <ul>
                        {client.redirect_uris.map((uri) => (
                          <li key={uri} className="max-w-[16rem] truncate font-mono text-xs" title={uri}>
                            {uri}
                          </li>
                        ))}
                      </ul>
                    )}
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex flex-wrap justify-end gap-1">
                      <button type="button" className="btn-ghost" onClick={() => setEditing(client)}>
                        Edit
                      </button>
                      {usesSecret(client.token_endpoint_auth_method) && (
                        <button type="button" className="btn-ghost" onClick={() => rotate(client)}>
                          Rotate secret
                        </button>
                      )}
                      <button type="button" className="btn-ghost" onClick={() => revokeTokens(client)}>
                        Revoke tokens
                      </button>
                      <button type="button" className="btn-ghost text-red-600 dark:text-red-400" onClick={() => remove(client)}>
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {editing && <ClientDialog client={editing === 'new' ? null : editing} info={info} onClose={() => setEditing(null)} onSaved={saved} />}
      {secret && <SecretDialog clientId={secret.clientId} secret={secret.secret} onClose={() => setSecret(null)} />}
    </section>
  )
}

function ClientDialog({
  client,
  info,
  onClose,
  onSaved,
}: {
  client: Client | null
  info: Info
  onClose: () => void
  onSaved: (client: Client) => void
}) {
  const [id, setId] = useState(client?.id ?? '')
  const [method, setMethod] = useState<AuthMethod>(client?.token_endpoint_auth_method ?? 'client_secret_basic')
  const [redirectURIs, setRedirectURIs] = useState((client?.redirect_uris ?? []).join('\n'))
  const [postLogoutURIs, setPostLogoutURIs] = useState((client?.post_logout_redirect_uris ?? []).join('\n'))
  const [jwksURI, setJwksURI] = useState(client?.jwks_uri ?? '')
  const [publicKeys, setPublicKeys] = useState((client?.public_keys ?? []).join('\n'))
  const [grants, setGrants] = useState<string[]>(client?.grant_types ?? ['authorization_code', 'refresh_token'])
  const toggleGrant = (value: string) =>
    setGrants((current) => (current.includes(value) ? current.filter((g) => g !== value) : [...current, value]))
  const [saving, setSaving] = useState(false)
  const run = useAction()

  const methodChangesSecret = client !== null && usesSecret(method) && (!client.has_secret || isJWT(method) !== isJWT(client.token_endpoint_auth_method))

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setSaving(true)
    const input = {
      id: id.trim(),
      token_endpoint_auth_method: method,
      redirect_uris: lines(redirectURIs),
      post_logout_redirect_uris: lines(postLogoutURIs),
      jwks_uri: method === 'private_key_jwt' ? jwksURI.trim() : '',
      public_keys: method === 'private_key_jwt' ? (publicKeys.match(PEM) ?? []) : [],
      grant_types: grants,
    }
    let result: Client | undefined
    const ok = await run(async () => {
      result = client ? await api.updateClient(client.id, input) : await api.createClient(input)
    }, client ? 'Client saved' : 'Client created')
    setSaving(false)
    if (ok && result) onSaved(result)
  }

  return (
    <Modal
      title={client ? `Edit ${client.id}` : 'New client'}
      onClose={onClose}
      wide
      footer={
        <>
          <button type="button" className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form="client-form" className="btn-primary" disabled={saving}>
            {saving ? 'Saving…' : 'Save'}
          </button>
        </>
      }
    >
      <form id="client-form" onSubmit={submit} className="grid gap-4">
        <Field label="Client ID" htmlFor="client-id">
          <input id="client-id" className="input" required disabled={client !== null} value={id} onChange={(e) => setId(e.target.value)} />
        </Field>

        <Field
          label="Authentication method"
          htmlFor="auth-method"
          hint={
            <>
              {authMethods.find((m) => m.value === method)?.description}
              {!client && usesSecret(method) && '. The secret is generated when the client is saved.'}
              {methodChangesSecret && '. A new secret will be generated.'}
            </>
          }
        >
          <select id="auth-method" className="input" value={method} onChange={(e) => setMethod(e.target.value as AuthMethod)}>
            {authMethods
              .filter((m) => m.value !== '' || client?.token_endpoint_auth_method === '')
              .map((m) => (
                <option key={m.value} value={m.value}>
                  {m.label}
                </option>
              ))}
          </select>
        </Field>

        <fieldset>
          <legend className="label">Grant types</legend>
          <div className="grid gap-2 sm:grid-cols-2">
            {grantTypes.map((g) => {
              const disabled =
                (g.discouraged === 'implicit' && !info.allow_implicit_flow) || (g.discouraged === 'password' && !info.allow_password_grant)
              return (
                <label key={g.value} className={`flex items-start gap-2 text-sm ${disabled ? 'opacity-60' : ''}`}>
                  <input type="checkbox" className="mt-0.5" checked={grants.includes(g.value)} onChange={() => toggleGrant(g.value)} />
                  <span>
                    {g.label}
                    <span className="block text-xs text-slate-500 dark:text-slate-400">
                      {g.description}
                      {disabled && ' — disabled in the configuration (grants section)'}
                    </span>
                  </span>
                </label>
              )
            })}
          </div>
        </fieldset>

        <Field label="Redirect URIs" htmlFor="redirect-uris" hint="One per line. Leave it empty for resource servers that only introspect tokens.">
          <textarea
            id="redirect-uris"
            className="input font-mono"
            rows={3}
            value={redirectURIs}
            onChange={(e) => setRedirectURIs(e.target.value)}
            placeholder="https://app.example.com/callback"
          />
        </Field>

        <Field label="Post logout redirect URIs" htmlFor="post-logout-uris" hint="One per line">
          <textarea
            id="post-logout-uris"
            className="input font-mono"
            rows={2}
            value={postLogoutURIs}
            onChange={(e) => setPostLogoutURIs(e.target.value)}
          />
        </Field>

        {method === 'private_key_jwt' && (
          <>
            <Field label="JWKS URI" htmlFor="jwks-uri" hint="The URL of the client public keys, or paste them below">
              <input
                id="jwks-uri"
                type="url"
                className="input font-mono"
                value={jwksURI}
                onChange={(e) => setJwksURI(e.target.value)}
                placeholder="https://app.example.com/.well-known/jwks.json"
              />
            </Field>
            <Field label="Public keys" htmlFor="public-keys" hint="PEM public keys or certificates (RSA, EC or Ed25519)">
              <textarea
                id="public-keys"
                className="input font-mono text-xs"
                rows={6}
                value={publicKeys}
                onChange={(e) => setPublicKeys(e.target.value)}
                placeholder={'-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----'}
              />
            </Field>
          </>
        )}
      </form>
    </Modal>
  )
}

const isJWT = (method: AuthMethod) => method === 'client_secret_jwt'

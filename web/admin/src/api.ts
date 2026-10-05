// Client of the minioidc admin API (<issuer>/admin/api). The session cookie
// authenticates the requests, and the changes send the CSRF header.

export interface Info {
  name: string
  issuer: string
  admin_group: string
  users_readonly: boolean
  allow_implicit_flow: boolean
  allow_password_grant: boolean
  passkeys_enabled: boolean
  /** false with LDAP: the users cannot be listed */
  users_listable: boolean
  /** the passwords can be changed (the users are in SQLite) */
  passwords_manageable: boolean
  /** the groups of the users can be changed (the users are in SQLite) */
  groups_manageable: boolean
  event_retention_days: number
  me: { subject: string; preferred_username: string; name: string }
}

export interface User {
  subject: string
  preferred_username: string
  email: string
  email_verified: boolean
  name: string
  given_name: string
  family_name: string
  phone: string
  address: string
  groups: string[]
  has_password: boolean
  has_mfa: boolean
  passkeys: number
  /** too many failed attempts (automatic) */
  blocked: boolean
  admin: boolean
  disabled: boolean
  disabled_reason?: string
  disabled_at?: string
  disabled_by?: string
  /** locked by an administrator */
  locked: boolean
  /** empty: until it is unlocked */
  locked_until?: string
  lock_reason?: string
  locked_by?: string
  password_change_required: boolean
  last_login_at?: string
}

type UserStateFields =
  | 'disabled'
  | 'disabled_reason'
  | 'disabled_at'
  | 'disabled_by'
  | 'locked'
  | 'locked_until'
  | 'lock_reason'
  | 'locked_by'
  | 'password_change_required'
  | 'last_login_at'

export type UserInput = Omit<User, 'subject' | 'has_password' | 'has_mfa' | 'passkeys' | 'blocked' | 'admin' | UserStateFields> & {
  subject?: string
  password: string
}

export interface Session {
  id: string
  auth_time: string
  expires_at: string
  auth_methods: string[]
  mfa_pending: boolean
  current: boolean
}

export interface Passkey {
  id: string
  name: string
  created_at: string
  last_used_at: string | null
}

export type UserStatus = '' | 'admin' | 'disabled' | 'locked' | 'blocked' | 'mfa' | 'no_mfa' | 'passkeys' | 'temporary_password'

export interface UserQuery {
  q?: string
  status?: UserStatus
  limit?: number
  offset?: number
}

export interface UserPage {
  users: User[]
  /** the users of the search (all the pages) */
  total: number
}

export interface Overview {
  /** null when the users cannot be listed (LDAP) */
  users: {
    total: number
    admins: number
    disabled: number
    locked: number
    blocked: number
    with_mfa: number
    with_passkeys: number
    temporary_password: number
    never_signed_in: number
  } | null
  clients: number
  groups: number
  activity: EventSummary
  incidents: ActivityEvent[]
}

export interface Setting {
  key: string
  group: string
  label: string
  description?: string
  kind: 'bool' | 'int' | 'string'
  min?: number
  max?: number
  default: string
  /** the value of the file (the running one without a file) */
  value: string
  /** the value that the server is using */
  running: string
  /** the file reads it from an environment variable */
  from_env: boolean
  /** the file has a value that needs a restart */
  pending: boolean
}

export interface Settings {
  mode: 'file' | 'default'
  file?: string
  data_dir?: string
  editable: boolean
  read_only_reason?: string
  version?: string
  settings: Setting[]
  server: { label: string; value: string }[]
}

/** the URL of the configuration file generated from the running settings */
export const settingsExportURL = () => new URL('settings/config.yml', base).toString()

export interface Group {
  name: string
  description: string
  members: number
  /** the group of the administrators */
  admin: boolean
  /** the clients restricted to this group */
  clients: string[]
  /** false for the groups that only exist in the users */
  defined: boolean
}

export interface ActivityEvent {
  id: number
  time: string
  type: string
  result: 'success' | 'failure'
  user_id?: string
  username?: string
  client_id?: string
  actor?: string
  ip?: string
  user_agent?: string
  detail?: string
}

export interface EventPage {
  events: ActivityEvent[]
  /** the "before" of the next page, 0 if there are no more events */
  next: number
}

export interface EventQuery {
  user?: string
  q?: string
  type?: string
  result?: string
  since?: string
  until?: string
  before?: number
}

export interface EventSummary {
  logins: number
  failed_logins: number
  lockouts: number
  admin_actions: number
  account_changes: number
}

/** the query string of the non empty values */
const queryString = (query: object) => {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== '' && value !== 0) params.set(key, String(value))
  }
  return params.toString()
}

const eventParams = (query: EventQuery) => queryString(query)

/** the URL of the CSV export of the events (a GET: the session cookie authenticates it) */
export const eventsCSVURL = (query: EventQuery) => new URL(`events.csv?${eventParams(query)}`, base).toString()

export type AuthMethod = '' | 'client_secret_basic' | 'client_secret_post' | 'client_secret_jwt' | 'private_key_jwt' | 'none'

export interface Client {
  id: string
  token_endpoint_auth_method: AuthMethod
  redirect_uris: string[]
  post_logout_redirect_uris: string[]
  jwks_uri: string
  public_keys: string[]
  grant_types: string[]
  /** the groups whose members can use the client; empty: all the users */
  allowed_groups: string[]
  has_secret: boolean
  /** only returned when a secret is generated */
  secret?: string
}

export type ClientInput = Omit<Client, 'has_secret' | 'secret'>

export class ApiError extends Error {
  status: number
  /** the action needs a recent login of the administrator */
  reauthenticate: boolean

  constructor(status: number, message: string, reauthenticate = false) {
    super(message)
    this.status = status
    this.reauthenticate = reauthenticate
  }
}

// the page is served at <issuer>/admin/, so the API is at ./api
const base = new URL('api/', window.location.href.split('#')[0])

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (method !== 'GET') {
    headers['X-Minioidc-Admin'] = '1'
  }
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
  }

  const response = await fetch(new URL(path, base), {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  })

  if (response.status === 401) {
    // the session has expired: log in again and come back
    const page = window.location.pathname + window.location.hash
    window.location.href = new URL(`../login?return_url=${encodeURIComponent(page)}`, window.location.href).toString()
    throw new ApiError(401, 'Your session has expired')
  }

  if (!response.ok) {
    let message = response.statusText
    let reauthenticate = false
    try {
      const data = await response.json()
      message = data.error ?? message
      reauthenticate = data.reauthenticate === true
    } catch {
      // not a JSON error
    }
    throw new ApiError(response.status, message, reauthenticate)
  }

  if (response.status === 204) {
    return undefined as T
  }

  return (await response.json()) as T
}

const id = (value: string) => encodeURIComponent(value)

export const api = {
  info: () => request<Info>('GET', 'info'),

  users: (query: UserQuery = {}) => request<UserPage>('GET', `users?${queryString(query)}`),
  user: (subject: string) => request<User>('GET', `users/${id(subject)}`),
  overview: () => request<Overview>('GET', 'overview'),
  createUser: (input: UserInput) => request<User>('POST', 'users', input),
  updateUser: (subject: string, input: UserInput) => request<User>('PUT', `users/${id(subject)}`, input),
  deleteUser: (subject: string) => request<void>('DELETE', `users/${id(subject)}`),
  sessions: (subject: string) => request<Session[]>('GET', `users/${id(subject)}/sessions`),
  deleteSession: (subject: string, session: string) => request<void>('DELETE', `users/${id(subject)}/sessions/${id(session)}`),
  deleteSessions: (subject: string) => request<void>('DELETE', `users/${id(subject)}/sessions`),
  resetMFA: (subject: string) => request<void>('DELETE', `users/${id(subject)}/mfa`),
  unblock: (subject: string) => request<void>('POST', `users/${id(subject)}/unblock`),
  lock: (subject: string, until: string | null, reason: string) =>
    request<User>('POST', `users/${id(subject)}/lock`, { until: until ?? '', reason }),
  disable: (subject: string, reason: string) => request<User>('POST', `users/${id(subject)}/disable`, { reason }),
  enable: (subject: string) => request<User>('POST', `users/${id(subject)}/enable`, {}),
  setPassword: (subject: string, password: string, requireChange: boolean) =>
    request<User>('POST', `users/${id(subject)}/password`, { password, require_change: requireChange }),
  temporaryPassword: (subject: string) => request<{ password: string }>('POST', `users/${id(subject)}/temporary-password`, {}),
  resetLink: (subject: string) => request<{ url: string; expires_at: string }>('POST', `users/${id(subject)}/reset-link`, {}),
  passkeys: (subject: string) => request<Passkey[]>('GET', `users/${id(subject)}/passkeys`),
  deletePasskey: (subject: string, passkey: string) => request<void>('DELETE', `users/${id(subject)}/passkeys/${id(passkey)}`),
  deletePasskeys: (subject: string) => request<void>('DELETE', `users/${id(subject)}/passkeys`),

  clients: () => request<Client[]>('GET', 'clients'),
  createClient: (input: ClientInput) => request<Client>('POST', 'clients', input),
  updateClient: (clientID: string, input: ClientInput) => request<Client>('PUT', `clients/${id(clientID)}`, input),
  deleteClient: (clientID: string) => request<void>('DELETE', `clients/${id(clientID)}`),
  rotateSecret: (clientID: string) => request<Client>('POST', `clients/${id(clientID)}/secret`),
  revokeClientTokens: (clientID: string) => request<void>('DELETE', `clients/${id(clientID)}/tokens`),

  groups: () => request<Group[]>('GET', 'groups'),
  createGroup: (name: string, description: string) => request<Group>('POST', 'groups', { name, description }),
  updateGroup: (name: string, newName: string, description: string) =>
    request<void>('PUT', `groups/${id(name)}`, { name: newName, description }),
  deleteGroup: (name: string) => request<void>('DELETE', `groups/${id(name)}`),
  groupMembers: (name: string) => request<User[]>('GET', `groups/${id(name)}/members`),
  addGroupMembers: (name: string, subjects: string[]) => request<void>('POST', `groups/${id(name)}/members`, { subjects }),
  removeGroupMember: (name: string, subject: string) => request<void>('DELETE', `groups/${id(name)}/members/${id(subject)}`),

  events: (query: EventQuery) => request<EventPage>('GET', `events?${eventParams(query)}`),
  eventSummary: () => request<EventSummary>('GET', 'events/summary'),

  settings: () => request<Settings>('GET', 'settings'),
  updateSettings: (version: string, values: Record<string, string>) => request<Settings>('PUT', 'settings', { version, values }),

  purgeExpired: () => request<void>('POST', 'maintenance/purge'),
  logoutAll: () => request<void>('POST', 'maintenance/logout-all'),
}

export const authMethods: { value: AuthMethod; label: string; description: string }[] = [
  { value: 'client_secret_basic', label: 'client_secret_basic', description: 'Secret in the Authorization header' },
  { value: 'client_secret_post', label: 'client_secret_post', description: 'Secret in the request body' },
  { value: 'client_secret_jwt', label: 'client_secret_jwt', description: 'JWT signed with the secret (HMAC)' },
  { value: 'private_key_jwt', label: 'private_key_jwt', description: 'JWT signed with the client private key' },
  { value: 'none', label: 'none (public client)', description: 'SPAs and mobile apps: PKCE is required' },
  { value: '', label: 'client_secret_basic or client_secret_post', description: 'Default of the clients of the configuration' },
]

export const grantTypes: { value: string; label: string; description: string; discouraged?: 'implicit' | 'password' }[] = [
  { value: 'authorization_code', label: 'Authorization code', description: 'Web, SPA and mobile apps (with PKCE)' },
  { value: 'refresh_token', label: 'Refresh token', description: 'Renew the tokens (offline_access scope)' },
  { value: 'client_credentials', label: 'Client credentials', description: 'Services without user (confidential clients)' },
  { value: 'urn:ietf:params:oauth:grant-type:device_code', label: 'Device code', description: 'TVs and CLIs (RFC 8628)' },
  {
    value: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    label: 'JWT bearer',
    description: 'The client gets tokens of any user with an assertion signed with its keys (RFC 7523)',
  },
  { value: 'implicit', label: 'Implicit and hybrid', description: 'Discouraged (RFC 9700)', discouraged: 'implicit' },
  { value: 'password', label: 'Password', description: 'Discouraged (RFC 9700)', discouraged: 'password' },
]

export const usesSecret = (method: AuthMethod) =>
  method === '' || method === 'client_secret_basic' || method === 'client_secret_post' || method === 'client_secret_jwt'

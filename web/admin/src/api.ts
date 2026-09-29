// Client of the minioidc admin API (<issuer>/admin/api). The session cookie
// authenticates the requests, and the changes send the CSRF header.

export interface Info {
  name: string
  issuer: string
  admin_group: string
  users_readonly: boolean
  allow_implicit_flow: boolean
  allow_password_grant: boolean
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
  blocked: boolean
  admin: boolean
}

export type UserInput = Omit<User, 'subject' | 'has_password' | 'has_mfa' | 'blocked' | 'admin'> & {
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

export type AuthMethod = '' | 'client_secret_basic' | 'client_secret_post' | 'client_secret_jwt' | 'private_key_jwt' | 'none'

export interface Client {
  id: string
  token_endpoint_auth_method: AuthMethod
  redirect_uris: string[]
  post_logout_redirect_uris: string[]
  jwks_uri: string
  public_keys: string[]
  grant_types: string[]
  has_secret: boolean
  /** only returned when a secret is generated */
  secret?: string
}

export type ClientInput = Omit<Client, 'has_secret' | 'secret'>

export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
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
    try {
      message = (await response.json()).error ?? message
    } catch {
      // not a JSON error
    }
    throw new ApiError(response.status, message)
  }

  if (response.status === 204) {
    return undefined as T
  }

  return (await response.json()) as T
}

const id = (value: string) => encodeURIComponent(value)

export const api = {
  info: () => request<Info>('GET', 'info'),

  users: () => request<User[]>('GET', 'users'),
  createUser: (input: UserInput) => request<User>('POST', 'users', input),
  updateUser: (subject: string, input: UserInput) => request<User>('PUT', `users/${id(subject)}`, input),
  deleteUser: (subject: string) => request<void>('DELETE', `users/${id(subject)}`),
  sessions: (subject: string) => request<Session[]>('GET', `users/${id(subject)}/sessions`),
  deleteSession: (subject: string, session: string) => request<void>('DELETE', `users/${id(subject)}/sessions/${id(session)}`),
  deleteSessions: (subject: string) => request<void>('DELETE', `users/${id(subject)}/sessions`),
  resetMFA: (subject: string) => request<void>('DELETE', `users/${id(subject)}/mfa`),
  unblock: (subject: string) => request<void>('POST', `users/${id(subject)}/unblock`),

  clients: () => request<Client[]>('GET', 'clients'),
  createClient: (input: ClientInput) => request<Client>('POST', 'clients', input),
  updateClient: (clientID: string, input: ClientInput) => request<Client>('PUT', `clients/${id(clientID)}`, input),
  deleteClient: (clientID: string) => request<void>('DELETE', `clients/${id(clientID)}`),
  rotateSecret: (clientID: string) => request<Client>('POST', `clients/${id(clientID)}/secret`),
  revokeClientTokens: (clientID: string) => request<void>('DELETE', `clients/${id(clientID)}/tokens`),

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

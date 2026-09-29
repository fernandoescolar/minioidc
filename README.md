# minioidc

[![Go](https://img.shields.io/badge/go-1.26+-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

minioidc is a lightweight OpenID Connect (OIDC) / OAuth 2.0 authorization server designed to provide Single Sign-On (SSO) functionality for small or home networks. It is not a complete OIDC implementation, but it covers the most common grant types and endpoints.

Supported grant types:

| Grant type | RFC | Availability |
|---|---|---|
| Authorization Code + PKCE (`S256`) | [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) | Default. PKCE is mandatory for public clients |
| Refresh Token | [RFC 6749 §6](https://datatracker.ietf.org/doc/html/rfc6749#section-6) | Default. Rotated on every use unless `reuse_refresh_tokens` is set |
| Client Credentials | [RFC 6749 §4.4](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4) | Confidential clients with `client_credentials` in `grant_types` |
| Device Code | [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) | Clients with the device code grant type |
| JWT Bearer | [RFC 7523 §2.1](https://datatracker.ietf.org/doc/html/rfc7523#section-2.1) | Confidential clients with the jwt-bearer grant type and keys |
| Implicit and Hybrid | [OIDC Core §3.2, §3.3](https://openid.net/specs/openid-connect-core-1_0.html) | **Discouraged** ([RFC 9700](https://datatracker.ietf.org/doc/html/rfc9700)): `grants.implicit` and `implicit` in the client `grant_types` |
| Resource Owner Password | [RFC 6749 §4.3](https://datatracker.ietf.org/doc/html/rfc6749#section-4.3) | **Discouraged** (RFC 9700): `grants.password` and `password` in the client `grant_types` |

Each client can only use the grant types of its `grant_types` (by default `authorization_code` and `refresh_token`). The discouraged flows are also disabled in the whole server unless they are enabled in the `grants` section.

The supported scopes are `openid`, `profile` (`preferred_username`, `name`, `given_name`, `family_name`), `email` (`email`, `email_verified`), `address` (`address`), `phone` (`phone_number`), `groups` (`groups`) and `offline_access` (refresh tokens).

The authorization endpoint (GET and POST) supports the OIDC parameters:

- `prompt`: `none` (returns `login_required` or `interaction_required` instead of showing a page), `login` and `select_account` (the user logs in again) and `consent` (the consent is implicit: the clients are registered by the administrator).
- `max_age`: the user logs in again if the last login is older.
- `id_token_hint`: the user logs in again if the hinted user is not the logged in user.
- `login_hint`: prefills the username in the login page.
- `nonce` and `state` (optional, but `nonce` is required when an ID token is returned by the authorization endpoint), `display`, `ui_locales`, `claims_locales` and `acr_values` (accepted and ignored).
- `response_mode`: `query` (code flow) and `fragment` (required by the implicit and hybrid flows).
- `request` and `request_uri` are not supported (`request_not_supported` / `request_uri_not_supported`).

The responses include the `iss` parameter (RFC 9207). The ID token includes `auth_time`, `amr` (`pwd`, plus `otp` and `mfa` after the MFA verification), `azp`, `at_hash`, `c_hash` (hybrid flow), `sid` and `nonce`.

If a code or a rotated refresh token is used twice, all the refresh tokens issued from it are revoked (one of the requests could be from an attacker).

The token, userinfo, revocation, introspection, device authorization, discovery and JWKS endpoints allow CORS requests (without cookies), so they can be used from SPAs.

It also implements:

- *Client authentication*: `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt` (RFC 7523) and `none` (public clients).
- *Token introspection* (RFC 7662).
- *Token revocation* (RFC 7009) of refresh tokens. The access tokens are short lived JWTs: revoking them answers `unsupported_token_type`, and they stop working when their session is closed.
- *RP-Initiated Logout*, with `id_token_hint`, `post_logout_redirect_uri` and `state`. Without `id_token_hint`, the user confirms the logout.
- *Key rotation*: previous signing keys keep being published in the JWKS.

## Features

- **Simple and Lightweight**: minioidc is designed to be a straightforward solution for enabling SSO in small or home networks.
- **Onboarding**: Start it without a configuration file and create the administrator from the browser.
- **OAuth 2.0 grant types**: Authorization Code with PKCE, Refresh Token, Client Credentials, Device Code (RFC 8628) and JWT Bearer (RFC 7523), plus the discouraged Implicit, Hybrid and Password grants (disabled by default).
- **Client and User Configuration**: Configure clients and users in the YAML configuration file, or manage them from the admin web.
- **Flexible Data Storage**: Store the data in memory or in a SQLite v3 database: sessions, tokens, MFA, users and clients.
- **LDAP Users Integration**: Use the users of an LDAP server to log in.
- **LDAP server**: Serve the users as a read only LDAP directory, for the applications that only support LDAP.
- **MFA**: Require MFA for all users using TOTP App (e.g. Google Authenticator).
- **User profile**: The users change their password and manage their authenticator apps.
- **Responsive pages**: The login, MFA, device and profile pages work on phones and computers, with light and dark modes. The templates can be customized with the components of the design system.
- **Admin web**: Manage users, clients, sessions and tokens from a web served by minioidc, for the members of an admin group.
- **Brute force protection**: Logins, MFA codes, LDAP binds, password grants and device user codes are blocked for 15 minutes after 5 failed attempts.
- **Secure by Default**: Enable HTTP Strict Transport Security (HSTS), Content Security Policy (CSP), secure cookies, and more with a single configuration option.

## Endpoints

The endpoints are published under the path of the issuer: if the issuer is `https://example.com/auth`, the discovery document is at `https://example.com/auth/.well-known/openid-configuration`.

| Endpoint | Path |
|---|---|
| Discovery | `/.well-known/openid-configuration` |
| JWKS | `/.well-known/jwks.json` |
| Authorization | `/connect/authorize` |
| Token | `/connect/token` |
| Userinfo | `/connect/userinfo` |
| Introspection (RFC 7662) | `/connect/introspect` |
| Revocation (RFC 7009) | `/connect/revoke` |
| End session (RP-Initiated Logout) | `/connect/endsession` |
| Device authorization (RFC 8628) | `/connect/deviceauthorization` |
| Device activation page | `/connect/device` |
| Login page | `/login` |
| MFA pages | `/mfa/create`, `/mfa/verify` |
| User profile | `/profile`, `/profile/password`, `/profile/mfa` |
| Admin web (optional) | `/admin/` |
| Health check | `/healthz` |

## Roadmap

- [x] OIDC Discovery
- [x] Authorization Code with PKCE
- [x] Refresh Token
- [x] CSRF
- [x] Yaml config file
- [x] ENV secrets inside yaml config file
- [x] Sqlite database for grants, sessions, MFA, users and clients
- [x] MFA with TOTP App (e.g. Google Authenticator)
- [ ] MFA with email?
- [x] Ldap Users integration
- [x] RP-Initiated Logout
- [x] Token revocation and introspection
- [x] Client credentials, device code and JWT bearer grants
- [x] Implicit, hybrid and password grants (disabled by default)
- [x] User profile (password and MFA)
- [x] `client_secret_jwt` and `private_key_jwt` client authentication
- [x] Signing key rotation
- [x] Admin web
- [x] LDAP server

## Requirements

- Go 1.26 or later (to run from source or to use it as a library)
- Node.js 24 or later, only to build the admin web and the stylesheet of the pages (`make build-admin`)
- Docker (optional, for the containerised setup)

## Installation

### From source

```bash
git clone https://github.com/fernandoescolar/minioidc.git
cd minioidc
make build-all      # builds the admin web and ./bin/minioidc
```

Without Node.js, `make build` builds the server: everything works except the admin web, that shows how to build it.

### Docker

```bash
make build-docker   # builds the image (with the admin web)
make run-docker     # starts the container on :8000 with example2_config.yml
```

Without a configuration file, the data is kept in the `/data` volume (see [Onboarding](#onboarding)):

```bash
docker run -p 8000:8000 -v minioidc-data:/data minioidc:latest
```

### As a Go library

```bash
go get github.com/fernandoescolar/minioidc
```

## Getting Started

### Without configuration

Run the server from the root of the repository (the paths of the templates and static files are relative to the working directory):

```bash
make build-all && ./bin/minioidc
```

The log shows a link like `http://localhost:8000/setup?code=ABCD-EFGH-IJKL-MNOP`: open it, create the administrator and follow the next steps (register your first application in the admin web, add an authenticator app…). See [Onboarding](#onboarding).

### With a configuration file

1. Copy the example configuration and edit the issuer, the clients and the users (see [Configuration](#configuration)):

```bash
cp example2_config.yml config.yml
```

2. Run the server from the root of the repository (the paths of the templates and static files are relative to the working directory):

```bash
MINIOIDC_CONFIG=config.yml make run
```

3. Visit [http://localhost:8000](http://localhost:8000). If you enable the LDAP server, publish its port too in Docker (e.g. `-p 3389:3389`).

## Makefile Commands

There are several commands available in the Makefile:

- `make build` - Build the binary
- `make build-admin` - Build the admin web (requires Node.js). It is embedded in the binary, so build it before `make build`
- `make build-all` - Build the admin web and the binary
- `make build-css` - Build the stylesheet of the pages (`static/styles.css`) after changing the templates
- `make run` - Run the binary
- `make build-docker` - Build the docker image (it builds the admin web too)
- `make run-docker` - Run the docker image
- `make test` - Run the tests
- `make clean` - Clean the binary
- `make lint` - Run the linter
- `make hash text=plain_text_to_hash` - Generate a hash from a given `text`

## Configuration

The server reads these environment variables (and the `.env` file, if it exists):

- `MINIOIDC_ADDR` - The address to listen on (default: `:8000`)
- `MINIOIDC_CONFIG` - The path to the yaml configuration file. Without it, the server starts with the [default configuration](#onboarding)
- `MINIOIDC_DATA` - Without `MINIOIDC_CONFIG`, the directory of the data (default: `data`, `/data` in Docker)
- `MINIOIDC_ISSUER` - Without `MINIOIDC_CONFIG`, the issuer (default: `http://localhost:<port>/`)
- `MINIOIDC_SETUP_CODE` - The code to create the first administrator (at least 12 characters). By default it is random and written in the log

The configuration file is a yaml file with the following structure:

```yaml
name: My MiniOIDC
masterkey: ${MINIOIDC_MASTERKEY} # at least 32 characters
issuer: https://sso.example.com
audience: https://sso.example.com
require_mfa: true
reuse_refresh_tokens: false
grants:
  implicit: false # the implicit and hybrid flows (discouraged)
  password: false # the resource owner password grant (discouraged)
private_rsa_key_path: private_key.pem
previous_rsa_key_paths: []
middlewares:
  hsts: true
  csp: true
  secure_cookies: true
  forward_headers: true
  log_requests: true
ttl:
  access: 20 # minutes
  refresh: 129600 # 90 days
  session: 129600 # 90 days
  code: 5 # minutes
  csrf: 5 # minutes
sqlite:
  filepath: db.sqlite3
  use_in_grants: true
  use_in_sessions: true
  use_in_mfa: true
  use_in_client_assertions: true
  use_in_users: true
  use_in_clients: true
admin:
  enabled: true
  group: admin
ldap_server:
  enabled: true
  address: :3389
  base_dn: dc=example,dc=com
  bind_dn: cn=service,dc=example,dc=com
  bind_password_hash: $2a$12$...
  allow_anonymous: false
  users_can_search: false
  tls:
    mode: starttls
    cert_path: /certificates/ldap.crt
    key_path: /certificates/ldap.key
templates:
  base: templates/base.html
  login: templates/login.html
  mfa_create: templates/mfa_create.html
  mfa_verify: templates/mfa_verify.html
  logout: templates/logout.html
  device: templates/device.html
  error: templates/error.html
  profile: templates/profile.html
  profile_password: templates/profile_password.html
  profile_mfa: templates/profile_mfa.html
  setup: templates/setup.html
clients:
  - id: myclient
    secret_hash: $2a$06$L6/zALdtbkYajjHTZUW29ePBEb/hwhgjhXC4YpHANavvKDJl69ctK # secret
    redirect_uris:
     - https://myapp.example.com/callback
    post_logout_redirect_uris:
     - https://myapp.example.com/
  - id: myspa
    token_endpoint_auth_method: none # public client: PKCE is required
    redirect_uris:
     - https://spa.example.com/callback
  - id: mytv
    token_endpoint_auth_method: none
    grant_types:
     - urn:ietf:params:oauth:grant-type:device_code
     - refresh_token
users:
  - subject: 1
    email: user@example.com
    email_verified: true
    preferred_username: user
    name: John Doe
    given_name: John
    family_name: Doe
    password_hash: $2a$06$03dduqc0lMbsb5go/l6RI.cRb03Hos9CMpgm5/yYuRsSQPHtrFwSq # password
    phone: +1234567890
    address: 1 Main St. City, State 12345
    groups:
      - admin
```

The yaml configuration file can also reference environment variables:

```yaml
value1: ${ENV_VAR}
value2: $OTHER_ENV_VAR
```

### Root settings

- `name` - The display name of the server (used in the pages and as TOTP issuer)
- `masterkey` - The key used to encrypt cookies, CSRF tokens and the `client_secret_jwt` secrets. It must have at least 32 characters. If it is not set, a random one is generated, and the sessions do not survive a restart
- `issuer` - The OIDC issuer: an `http(s)` URL without query or fragment. The endpoints are published under its path
- `audience` - The audience of the access tokens (ID tokens use the client ID as audience)
- `require_mfa` - Whether to require MFA for all users (default: `false`)
- `reuse_refresh_tokens` - Whether to allow re-use refresh tokens (default: `false`)
- `grants.implicit` - Whether the clients with the `implicit` grant type can use the implicit and hybrid flows (default: `false`). They are discouraged by RFC 9700: the tokens are sent through the browser
- `grants.password` - Whether the clients with the `password` grant type can use the resource owner password grant (default: `false`). It is discouraged by RFC 9700: the client sees the password of the user. The users with MFA write their TOTP code at the end of the password, and the failed attempts count as failed logins
- `private_rsa_key_path` - The path to the private RSA key, PKCS#1 or PKCS#8 PEM (if not set, a new random key will be generated)
- `previous_rsa_key_paths` - The paths to the previous signing keys (public or private PEM). To rotate the signing key, set the new key in `private_rsa_key_path` and move the old one here: tokens signed with it are still valid and it keeps being published in the JWKS. Remove it once its tokens have expired.

### `middlewares`

- `hsts` - Whether to enable HTTP Strict Transport Security (HSTS). It also redirects the HTTP requests to HTTPS (default: `false`)
- `csp` - Whether to enable Content Security Policy (CSP) and other security headers (default: `false`)
- `secure_cookies` - Whether to enable secure cookies (default: `false`)
- `forward_headers` - Whether to use the `X-Forwarded-*` and `Forwarded` headers of a reverse proxy (default: `false`)
- `log_requests` - Whether to log requests (default: `false`)

### `ttl`

- `access` - The access and ID tokens TTL in minutes (default: `20`)
- `refresh` - The refresh token TTL in minutes (default: `129600`, 90 days)
- `session` - The session TTL in minutes (default: `129600`, 90 days)
- `code` - The authorization code TTL in minutes (default: `5`)
- `csrf` - The CSRF token TTL in minutes (default: `5`)

### `sqlite`

- `filepath` - The path to the SQLite database file. It is mandatory if any `use_in_*` option is set to `true`. The database uses WAL mode, so the `-wal` and `-shm` files are created next to it. The tables are created and migrated on start up
- `use_in_grants` - Whether to store the codes, refresh tokens and device codes in the database (default: `false`)
- `use_in_sessions` - Whether to store the sessions in the database (default: `false`)
- `use_in_mfa` - Whether to store the MFA secrets in the database (default: `false`)
- `use_in_users` - Whether to store the users in the database, so they can be managed from the admin web (default: `false`). It cannot be used with LDAP users
- `use_in_clients` - Whether to store the clients in the database, so they can be managed from the admin web (default: `false`)
- `use_in_client_assertions` - Whether to store the used `jti` of the `client_secret_jwt` and `private_key_jwt` assertions in the database (default: `false`). Enable it when several instances share the database, so an assertion used in one instance cannot be replayed in another one

> With `use_in_users` and `use_in_clients`, the users and clients of the configuration file are only added to the database when they do not exist: after that, the database is the source of truth, so the changes made in the admin web are kept after a restart.

> Several instances can share the SQLite file only in a local file system (not a network file system like NFS or SMB, where the SQLite locks are not reliable).

### `ldap` (LDAP users)

Use the users of an LDAP server to log in:

```yaml
ldap:
  server: localhost:389
  bind: uid=admin,cn=users,dc=example,dc=com
  password: ${LDAP_PASSWORD}
  base_dn: dc=example,dc=com
  filter_dn: (&(uid={username})(objectClass=person))
  email_verified: false
  attributes:
    subject: uidNumber
    name: uid
    display_name: cn
    given_name: givenName
    family_name: sn
    email: mail
    phone: telephoneNumber
    address: postalAddress
    groups: memberOf
```

- `server` - The LDAP server address
- `bind` - The LDAP bind DN
- `password` - The LDAP bind password
- `base_dn` - The LDAP base DN
- `filter_dn` - The LDAP filter to find a user. `{username}` is replaced with the escaped username
- `email_verified` - Whether the emails of the directory are verified (default: `false`)
- `attributes.subject` - The LDAP attribute to use for the user subject
- `attributes.name` - The LDAP attribute to use for the username (`preferred_username` claim)
- `attributes.display_name` - Optional. The LDAP attribute to use for the `name` claim
- `attributes.given_name` - Optional. The LDAP attribute to use for the `given_name` claim
- `attributes.family_name` - Optional. The LDAP attribute to use for the `family_name` claim
- `attributes.email` - The LDAP attribute to use for the user email
- `attributes.phone` - The LDAP attribute to use for the user phone
- `attributes.address` - The LDAP attribute to use for the user address
- `attributes.groups` - Optional. The LDAP attribute with the groups of the user (e.g. `memberOf`)

> If you use LDAP users, you can not configure the `users` section, `sqlite.use_in_users` or the `ldap_server` section.

### `templates`

- `base` - The base template
- `login` - The login page template
- `mfa_create` - The MFA create page template
- `mfa_verify` - The MFA verify page template
- `logout` - The logout page template
- `device` - The device activation page template
- `error` - The error pages template (e.g. not found)
- `profile`, `profile_password`, `profile_mfa` - The user profile page templates
- `setup` - The onboarding page template: the form of the first administrator and the next steps

The paths are relative to the working directory: if a template does not exist, minioidc does not start.

> In your templates, use `{{ basePath }}` to build the local URLs (e.g. `{{ basePath }}/static/styles.css`), so they work when the issuer has a path.

The pages and the admin web share a design system built with [Tailwind CSS](https://tailwindcss.com) (`web/theme/components.css`), with light and dark modes that follow the system. `static/styles.css` has all its components, so your templates can use them without compiling the stylesheet:

| Classes | Use |
|---|---|
| `page`, `page-brand`, `page-card`, `page-title`, `page-subtitle`, `page-footer` | The layout of `base.html`: a centered card |
| `stack`, `menu`, `menu-item` | Vertical spacing and lists of options |
| `btn-primary`, `btn-secondary`, `btn-danger`, `btn-ghost`, `btn-block` | Buttons |
| `label`, `input`, `code-input`, `hint` | Forms (`code-input` is the 6-digit code input) |
| `alert-error`, `alert-success`, `alert-warning`, `alert-info` | Messages |
| `card`, `badge`, `link`, `brand-mark`, `qr`, `secret`, `step`, `step-done` | Other components |

If you use other Tailwind classes in your templates, compile the stylesheet with `make build-css`.

> You can add your static files (like css, js, images, ...) in the `static` folder and use them in your templates (e.g. `<link rel="stylesheet" href="{{ basePath }}/static/css/style.css">`).

### `clients`

The OIDC clients. Each client has the following properties:

- `id` - The client ID
- `secret_hash` - The client secret hash (use the `make hash` command to generate a hash). Leave it empty for public clients (SPAs, mobile apps): they must use PKCE
- `redirect_uris` - The list of allowed redirect URIs. Leave it empty for resource servers that only introspect tokens
- `post_logout_redirect_uris` - The list of allowed redirect URIs after logout
- `token_endpoint_auth_method` - The only authentication method the client can use: `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt` or `none`. If it is not set, the client can use `client_secret_basic` and `client_secret_post` when it has `secret_hash`, or `none` otherwise
- `secret` - The plain secret, only for `client_secret_jwt` (at least 32 characters). The assertions are signed with HMAC, so the server needs the secret itself: use an environment variable (e.g. `secret: ${MYCLIENT_SECRET}`)
- `jwks_uri` - For `private_key_jwt`: the URL of the client JWKS. It is cached for 10 minutes and downloaded again when an assertion uses an unknown key (at most once per minute)
- `public_key_paths` - For `private_key_jwt`: PEM files with the public keys (RSA, EC or Ed25519) or certificates of the client
- `grant_types` - The grant types the client can use (default: `authorization_code` and `refresh_token`): `authorization_code`, `refresh_token`, `client_credentials` (confidential clients), `urn:ietf:params:oauth:grant-type:device_code`, `urn:ietf:params:oauth:grant-type:jwt-bearer` (with keys), `implicit` and `password` (these two also need the `grants` section)

The JWT bearer grant (RFC 7523 section 2.1) lets a client get tokens of any user with an assertion signed with its own keys (`jwks_uri`, `public_key_paths` or the `client_secret_jwt` secret): `iss` is the client ID, `sub` the subject of the user, `aud` the issuer or the token endpoint URL, and it needs a unique `jti` and an `exp`. It issues no ID token (the user has not authenticated). Enable it only for trusted clients.

The device flow (RFC 8628) shows the user code as `XXXX-XXXX` (the users can type it in lowercase and without the dash). The users confirm the client and the permissions in `/connect/device` before authorizing it. The device codes are grants: they are stored with the codes and refresh tokens (in SQLite with `sqlite.use_in_grants`, so they are kept after a restart and shared by the instances that use the same database). They expire in 10 minutes.

```yaml
clients:
  - id: backend
    token_endpoint_auth_method: private_key_jwt
    jwks_uri: https://backend.example.com/.well-known/jwks.json
    redirect_uris:
      - https://backend.example.com/callback
  - id: worker
    token_endpoint_auth_method: client_secret_jwt
    secret: ${WORKER_SECRET}
    redirect_uris:
      - https://worker.example.com/callback
  - id: my-api # a resource server that only introspects tokens
    secret_hash: $2a$12$...
```

The JWT assertions (`client_assertion`) must have `iss` and `sub` equal to the client ID, `aud` equal to the issuer, the token endpoint URL or the URL of the endpoint where they are used, a unique `jti` and an `exp` at most one hour ahead. Each `jti` can only be used once: the used ones are kept in memory, or in SQLite with `use_in_client_assertions`.

The introspection endpoint can be used by any confidential client to introspect access tokens (e.g. resource servers registered as clients without redirect URIs). Refresh tokens can only be introspected by the client they were issued to. Public clients cannot use it.

### `users`

The users to log in. Each user has the following properties:

- `subject` - The user subject (`sub` claim)
- `preferred_username` - The username used to log in
- `password_hash` - The password hash (use the `make hash` command to generate a hash)
- `email` - The user email
- `email_verified` - Whether the user email is verified (default: `false`)
- `name`, `given_name`, `family_name` - Optional. The user names
- `phone` - The user phone number
- `address` - The user address
- `groups` - The list of user groups (`groups` claim). The members of the admin group can use the admin web

### `admin`

- `enabled` - Whether to serve the admin web at `<issuer>/admin/` (default: `false`). It requires `sqlite.use_in_clients`
- `group` - The group of the administrators (default: `admin`)

See [Admin web](#admin-web).

### `ldap_server`

- `enabled` - Whether to serve the users as an LDAP directory (default: `false`)
- `address` - The address to listen on (default: `:3389`)
- `base_dn` - The base DN of the directory (e.g. `dc=example,dc=com`)
- `bind_dn` and `bind_password_hash` - Optional. The service account the applications use to search the directory (use the `make hash` command to generate the hash)
- `allow_anonymous` - Whether anonymous clients can search the directory (default: `false`)
- `users_can_search` - Whether the users bound with their own credentials can search all the directory (default: `false`: they can only read their own entry)
- `tls.mode` - `""` (plain LDAP), `ldaps` or `starttls`
- `tls.cert_path` and `tls.key_path` - The PEM certificate and private key for `ldaps` and `starttls`

See [LDAP server](#ldap-server).

## Admin web

When the clients (and optionally the users) are stored in SQLite, minioidc can serve an admin web at `<issuer>/admin/`:

```yaml
admin:
  enabled: true
  group: admin # default: admin
sqlite:
  filepath: minioidc.sqlite3
  use_in_users: true   # manage the users (not available with LDAP)
  use_in_clients: true # required by the admin web
  use_in_grants: true
  use_in_sessions: true
  use_in_mfa: true
  use_in_client_assertions: true
```

Only the members of the admin group can use it (with the MFA verified, if it is required). With LDAP users, map the groups with `ldap.attributes.groups` (e.g. `memberOf`): the admin group can be the group DN or its name (e.g. `admin` matches `cn=admin,ou=groups,dc=example,dc=com`).

From the admin web you can:

- **Users**: create, edit and delete users, change their passwords and groups, see and close their sessions, reset their MFA and unblock them. The users of LDAP or of the configuration file (without `use_in_users`) are read only.
- **Clients**: create, edit and delete clients, rotate their secrets (the secrets are generated by the server and shown only once) and revoke their tokens.
- **Maintenance**: purge the expired data and log out all the users.

A client of the configuration file deleted in the admin web is added again in the next start: remove it from the configuration file too.

The admin web is in `web/admin` (TypeScript, React, Vite and Tailwind CSS) and it is embedded in the binary: run `make build-admin` before `make build` (the docker image builds it). Without it, `/admin/` shows how to build it. To develop it, run minioidc at `http://localhost:8000`, log in as an administrator and run `npm run dev` in `web/admin`: the API requests are proxied to minioidc.

## Onboarding

When the users are stored in SQLite (`sqlite.use_in_users`) and there are none, minioidc starts the onboarding:

1. It writes a link with a setup code in the log: `There are no users yet: create the administrator at http://localhost:8000/setup?code=ABCD-EFGH-IJKL-MNOP`. Only who can read the log (who runs the server) can use it.
2. Until the administrator exists, the login page sends to `<issuer>/setup`, where the setup code (if you do not open the link), the username, the name, the email and the password are asked.
3. The administrator is created in the admin group (`admin.group`) and signed in (with `require_mfa`, the authenticator app is added first). The welcome page shows the next steps: register the first application in the admin web, add an authenticator app, and the issuer and discovery URLs for the applications.

After that, `/setup` is closed. Set `MINIOIDC_SETUP_CODE` to choose the code (e.g. in automated deployments); otherwise, a new random one is generated in every start while there are no users. The users of the configuration file are added before, so there is no onboarding when there are users in `users`.

### Default configuration

Without `MINIOIDC_CONFIG`, minioidc starts with this configuration, so you only need the binary (or the docker image) to try it:

- All the data in SQLite (`<MINIOIDC_DATA>/minioidc.sqlite3`): users, clients, sessions, grants, MFA and client assertions.
- The admin web enabled, for the `admin` group.
- The master key (`masterkey`) and the signing key (`private.pem`) generated in the first start and kept in `MINIOIDC_DATA` (only readable by the owner): back them up with the database.
- The issuer and the audience from `MINIOIDC_ISSUER`.
- The Content Security Policy enabled, and with an `https` issuer, the secure cookies and HSTS.

When you need more options (LDAP, the LDAP server, MFA required, TTLs…), write a configuration file with the same `sqlite.filepath`, `masterkey` and `private_rsa_key_path`: the users and clients created in the admin web are kept.

## LDAP server

minioidc can serve its users (from SQLite or the configuration file, not from LDAP) as a read only LDAP directory, so the applications that only support LDAP (NAS, media servers, git servers…) can use the same users:

```yaml
ldap_server:
  enabled: true
  address: :3389                           # default
  base_dn: dc=example,dc=com
  bind_dn: cn=service,dc=example,dc=com    # service account for the applications (optional)
  bind_password_hash: $2a$12$...           # make hash text=...
  allow_anonymous: false                   # anonymous searches (default: false)
  users_can_search: false                  # the users can search all the directory (default: only their own entry)
  tls:
    mode: starttls                         # "" (plain LDAP), ldaps or starttls
    cert_path: /certificates/ldap.crt
    key_path: /certificates/ldap.key
```

The directory has this structure:

```
dc=example,dc=com
├── ou=users    uid=<username>  (inetOrgPerson: uid, cn, sn, givenName, displayName, mail,
│                                telephoneNumber, postalAddress, memberOf, employeeNumber = OIDC subject)
└── ou=groups   cn=<group>      (groupOfNames: cn, member)
```

- **Bind**: the service account, the users (`uid=<username>,ou=users,<base dn>` or just the username) and anonymous binds. The passwords are never published.
- **MFA**: an LDAP bind cannot ask for a second factor, so the users with MFA (or all the users with `require_mfa`) must write their TOTP code at the end of the password: `mypassword123456`. With `require_mfa`, the users that have not enrolled an authenticator app yet cannot bind.
- **Brute force protection**: the failed binds count as failed logins: the user is blocked for 15 minutes after 5 failures, both in LDAP and in the login page.
- **Search**: base, one level and subtree searches with any filter, attribute selection and size limit. The changes are visible at once (e.g. a user created in the admin web).
- **Read only**: add, modify and delete answer `unwillingToPerform`.

> Without TLS, the passwords are sent in clear text: use `ldaps` or `starttls` unless the network is trusted. With `starttls`, the clients must start TLS before sending credentials.

## Upgrading from previous versions

The databases are migrated on start up, including the SQLite databases of all the previous versions: make a backup first. Read the changes of your version:

### Everybody

- The users sign in again: the cookies, codes, refresh tokens and CSRF tokens of previous versions are no longer valid (they are encrypted with AES-GCM and the tokens are stored hashed).
- `issuer` and `audience` are required, and the `masterkey` must have at least 32 characters.
- The clients can only use the grant types of their `grant_types` (default: `authorization_code` and `refresh_token`): add `client_credentials`, the device code or the JWT bearer grant types to the clients that use them.
- The Implicit, Hybrid and Password grants are disabled by default: enable them in the `grants` section and in the `grant_types` of the clients that need them.
- PKCE `plain` is no longer supported (only `S256`), and it is required for the public clients.
- `email_verified` is `false` unless it is set in the users (or in `ldap.email_verified`).
- `phone_number` and `address` are returned with the `phone` and `address` scopes (not with `profile`), and `address` is a JSON object (`{"formatted": "..."}`).
- The endpoints are published under the path of the issuer. The OAuth endpoints are under `/connect/` (`/connect/authorize`, `/connect/token`…, see [Endpoints](#endpoints)): the clients that use the discovery document are not affected.
- The MFA enrollments with the SHA256 TOTP of previous versions keep working. The new ones use SHA1, supported by every authenticator app.
- **Templates**: the pages have a new design and there is a new `error` template. The Content Security Policy does not allow inline scripts any more: if you have custom templates, move their scripts to files in `static/` and use `{{ basePath }}` in their URLs.

### From the versions with the Device Code and Password grants

These versions had security issues, fixed now. The behaviour of some endpoints is now the standard one, so check your clients:

- The token endpoint authenticates the clients in all the grants, and the codes, refresh tokens and device codes can only be used by the client that received them, and only once.
- `expires_in` is in seconds (it was in nanoseconds), and the ID tokens live as long as the access tokens (they lived as long as the refresh tokens).
- The errors follow RFC 6749: `invalid_grant` is a 400 (it was a 401), an unknown grant type is `unsupported_grant_type`, and the errors of the authorization endpoint are redirected to the client once the client and the `redirect_uri` are valid.
- The introspection returns `"active": false` as a boolean (it was a string), does not accept ID tokens and needs a confidential client.
- The revocation answers 200 (it was 204) and revoking an access token answers `unsupported_token_type`: they are short lived JWTs that stop working when their session is closed.
- The JWT bearer grant only accepts assertions signed by the client (RFC 7523), not the tokens of minioidc, and it issues no ID token.
- The Client Credentials tokens have no user scopes and no refresh token.
- The logout validates `post_logout_redirect_uri` with the registered `post_logout_redirect_uris`, and without `id_token_hint` the user confirms it.
- Removing an authenticator app in the profile requires a code of a current one.

## Use in your projects

You can use the `minioidc` package in your projects to add OIDC authentication to your web applications:

```go
package main

import (
	"log"
	"net/http"

	"github.com/fernandoescolar/minioidc/pkg/api"
)

func main() {
	builder := &api.Builder{
		Audience:  "https://api.example.com",
		Issuer:    "https://minioidc.example.com",
		MasterKey: "a master key of at least 32 characters",
		Clients: []api.Client{
			{
				ID:           "myclient",
				SecretHash:   "$2a$06$L6/zALdtbkYajjHTZUW29ePBEb/hwhgjhXC4YpHANavvKDJl69ctK", // secret
				RedirectURIs: []string{"https://api.example.com/callback"},
			},
		},
		Users: []api.User{
			{
				Subject:           "0000001",
				PreferredUsername: "user",
				PasswordHash:      "$2a$06$03dduqc0lMbsb5go/l6RI.cRb03Hos9CMpgm5/yYuRsSQPHtrFwSq", // password
			},
		},
	}

	minioidc, err := builder.Build()
	if err != nil {
		log.Fatal(err)
	}
	defer minioidc.Close()

	// optional: only if builder.LDAPServer is set
	if err := minioidc.StartLDAPServer(); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	handler := minioidc.Wrap(mux)

	log.Printf("Listening http://localhost:8000")
	err = http.ListenAndServe(":8000", handler)
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
```

The builder has the following fields:

- `Name string` - The display name (default: `minioidc`)
- `MasterKey string` - The key to encrypt the internal data, at least 32 characters (if not set, a new random key will be generated)
- `Issuer string` - The OIDC issuer (MANDATORY)
- `Audience string` - The audience of the access tokens (MANDATORY)
- `RequireMFA bool` - Whether to require MFA for all users (default: `false`)
- `ReuseRefreshTokens bool` - Whether to allow re-use refresh tokens (default: `false`)
- `AllowImplicitFlow`, `AllowPasswordGrant bool` - Enable the discouraged flows (default: `false`)
- `PrivateRSAKey *rsa.PrivateKey` or `PrivateRSAKeyFilepath string` - The signing key (if not set, a new random key will be generated)
- `PreviousRSAPublicKeys []*rsa.PublicKey` and `PreviousRSAKeyFilepaths []string` - The previous signing keys (key rotation)
- `UseHSTS`, `UseCSP`, `UseSecureCookie`, `UseForwardedHeaders`, `LogRequests bool` - The middlewares (default: `false`)
- `AccessTTL`, `RefreshTTL`, `SessionTTL`, `CodeTTL`, `CSRFTTL time.Duration` - The TTLs
- `BaseTemplateFilepath`, `LoginTemplateFilepath`, `MFACreateTemplateFilepath`, `MFAVerifyTemplateFilepath`, `LogoutTemplateFilepath`, `DeviceTemplateFilepath`, `ProfileTemplateFilepath`, `ProfilePasswordTemplateFilepath`, `ProfileMFATemplateFilepath string` - The templates
- `ClientStore`, `UserStore`, `GrantStore`, `SessionStore`, `MFACodeStore`, `UserBlockedStore`, `ClientAssertionStore`, `DeviceCodeStore` - Custom stores (default: in memory, or SQLite with `UseSQLite`)
- `Clients []Client` - The clients: `ID`, `SecretHash`, `Secret`, `RedirectURIs`, `PostLogoutRedirectURIs`, `TokenEndpointAuthMethod`, `JWKSURI`, `PublicKeyPaths`, `PublicKeys` and `GrantTypes`
- `Users []User` - The users: `Subject`, `PreferredUsername`, `PasswordHash`, `Email`, `EmailVerified`, `Name`, `GivenName`, `FamilyName`, `Phone`, `Address` and `Groups`
- `AdminEnabled bool` and `AdminGroup string` - The admin web
- `LDAPServer *domain.LDAPServerConfig` - The LDAP server (nil to disable it)

And the builder has the following methods:

- `UseSQLite(string, SqliteDatabases)` - Set the SQLite database file path and the data stored in it (flags: `NoSqliteDatabases`, `Grants`, `Sessions`, `MFA`, `ClientAssertions`, `Users`, `Clients` or `All`, e.g. `api.Grants | api.Sessions`)
- `UseLDAP(string, LDAPConfig)` - Set the LDAP server address and LDAP config to use

The `LDAPConfig` struct has the following fields:

- `Bind string` - The LDAP bind DN
- `Password string` - The LDAP bind password
- `BaseDN string` - The LDAP base DN
- `FilterDN string` - The LDAP filter to find a user (`{username}` is replaced with the escaped username)
- `SubjectAttribute string` - The LDAP attribute to use for the user subject
- `NameAttribute string` - The LDAP attribute to use for the username (`preferred_username`)
- `DisplayNameAttribute`, `GivenNameAttribute`, `FamilyNameAttribute string` - Optional. The attributes of the user names
- `EmailAttribute string` - The LDAP attribute to use for the user email
- `PhoneAttribute string` - The LDAP attribute to use for the user phone
- `AddressAttribute string` - The LDAP attribute to use for the user address
- `GroupsAttribute string` - Optional. The LDAP attribute with the groups of the user
- `EmailVerified bool` - Whether the emails of the directory are verified

The `Minioidc` returned by `Build()` has the following methods:

- `Handler() http.Handler` - A handler with all the endpoints
- `Wrap(*http.ServeMux) http.Handler` - Adds the endpoints to your mux
- `StartLDAPServer() error` - Starts the LDAP server, if it is configured
- `Close()` - Stops the background jobs and the LDAP server
- `CleanExpired()` - Removes the expired data (it also runs every hour)

## Testing

```bash
make test                                  # all the tests
go test ./tests/integration/...            # the end to end tests of the flows
go test -race ./...                        # with the race detector
```

The integration tests (`tests/integration`) run a server with all the grant types enabled and test the flows as a client. `pkg/api` has the end to end tests of the configuration features (SQLite, admin web, LDAP server, issuer path…).

## Security

minioidc is intended for **small / home networks** and has not undergone a formal security audit. For production use, please review the following:

- Run it behind a TLS-terminating reverse proxy (nginx, Caddy, Traefik) and enable `secure_cookies`, `hsts` and `csp` (and `forward_headers`, so it knows the original scheme).
- Use a strong, random `masterkey` (32+ characters) and keep it secret: it encrypts the cookies and the `client_secret_jwt` secrets.
- Keep the RSA private key outside the repository and rotate it with `previous_rsa_key_paths`.
- Enable MFA (`require_mfa`) and keep the discouraged grants (`grants`) disabled unless a client really needs them.
- Enable the JWT bearer grant only for trusted clients: they can get tokens of any user.
- Use `ldaps` or `starttls` in the LDAP server unless the network is trusted.

The server protects against brute force attacks (5 failed attempts block a user for 15 minutes), CSRF, open redirects, token replays (a reused code or refresh token revokes its family) and clickjacking.

To report a vulnerability, please open a GitHub issue marked **[SECURITY]** or contact the maintainer directly.

## Contributing

Contributions are welcome. Please:

1. Fork the repository and create a feature branch.
2. Add tests for any new functionality (`tests/integration` for the flows, `pkg/api` for the configuration features).
3. Run `make lint` and `make test` and ensure both pass. If you change the templates or the admin web, run `make build-admin`.
4. Open a pull request with a clear description of the change.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

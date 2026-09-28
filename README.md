# minioidc

minioidc is a lightweight OpenID Connect (OIDC) server designed to provide Single Sign-On (SSO) functionality for small or home networks. While not a complete OIDC implementation, minioidc currently supports the following grant types:

- *Authorization Code with PKCE*: Securely obtain an authorization code using Proof Key for Code Exchange (PKCE, `S256` only). PKCE is mandatory for public clients (clients without secret).
- *Refresh Token*: Extend the validity of access tokens using refresh tokens (rotated on every use unless `reuse_refresh_tokens` is set).

The supported scopes are `openid`, `profile` (`preferred_username`, `name`, `given_name`, `family_name`), `email` (`email`, `email_verified`), `address` (`address`), `phone` (`phone_number`), `groups` (`groups`) and `offline_access` (refresh tokens).

The authorization endpoint (GET and POST) supports the OIDC parameters:

- `prompt`: `none` (returns `login_required` or `interaction_required` instead of showing a page), `login` and `select_account` (the user logs in again) and `consent` (the consent is implicit: the clients are registered by the administrator).
- `max_age`: the user logs in again if the last login is older.
- `id_token_hint`: the user logs in again if the hinted user is not the logged in user.
- `login_hint`: prefills the username in the login page.
- `nonce` and `state` (both optional), `display`, `ui_locales`, `claims_locales` and `acr_values` (accepted and ignored).
- `request` and `request_uri` are not supported (`request_not_supported` / `request_uri_not_supported`), and only the `query` response mode is supported.

The responses include the `iss` parameter (RFC 9207). The ID token includes `auth_time`, `amr` (`pwd`, plus `otp` and `mfa` after the MFA verification), `azp`, `at_hash`, `sid` and `nonce`.

If a code or a rotated refresh token is used twice, all the refresh tokens issued from it are revoked (one of the requests could be from an attacker).

The token, userinfo, revocation, introspection, discovery and JWKS endpoints allow CORS requests (without cookies), so they can be used from SPAs.

It also implements:

- *Client authentication*: `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt` (RFC 7523) and `none` (public clients).
- *Token introspection* (RFC 7662).
- *Token revocation* (RFC 7009) of refresh tokens.
- *RP-Initiated Logout*, with `id_token_hint`, `post_logout_redirect_uri` and `state`.
- *Key rotation*: previous signing keys keep being published in the JWKS.

## Features

- **Simple and Lightweight**: minioidc is designed to be a straightforward solution for enabling SSO in small or home networks.
- **Client and User Configuration**: Configure clients and users in the YAML configuration file, or manage them from the admin web.
- **Flexible Data Storage**: Store the data in memory or in a SQLite v3 database: sessions, tokens, MFA, users and clients.
- **LDAP Users Integration**: Use the users of an LDAP server to log in.
- **LDAP server**: Serve the users as a read only LDAP directory, for the applications that only support LDAP.
- **MFA**: Require MFA for all users using TOTP App (e.g. Google Authenticator).
- **Admin web**: Manage users, clients, sessions and tokens from a web served by minioidc, for the members of an admin group.
- **Brute force protection**: Logins, MFA codes and LDAP binds are blocked for 15 minutes after 5 failed attempts.
- **Secure by Default**: Enable HTTP Strict Transport Security (HSTS), Content Security Policy (CSP), secure cookies, and more with a single configuration option.

## Endpoints

The endpoints are published under the path of the issuer: if the issuer is `https://example.com/auth`, the discovery document is at `https://example.com/auth/.well-known/openid-configuration`.

| Endpoint | Path |
|---|---|
| Discovery | `/.well-known/openid-configuration` |
| JWKS | `/.well-known/jwks.json` |
| Authorization | `/authorize` |
| Token | `/token` |
| Userinfo | `/userinfo` |
| Introspection (RFC 7662) | `/introspect` |
| Revocation (RFC 7009) | `/revoke` |
| End session (RP-Initiated Logout) | `/logout` |
| Login page | `/login` |
| MFA pages | `/mfa/create`, `/mfa/verify` |
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
- [x] `client_secret_jwt` and `private_key_jwt` client authentication
- [x] Signing key rotation
- [x] Admin web
- [x] LDAP server

## Getting Started

- You can create a docker image and run it with the following commands:

```bash
make build-docker && make run-docker
```

And then visit [http://localhost:8000](http://localhost:8000). If you enable the LDAP server, publish its port too (e.g. `-p 3389:3389`).

- You can also use the visual studio code launch configuration to run the server in debug mode.

- Or you can call the `make run` command to run the server directly. The paths of the templates and static files are relative to the working directory, so run it from the root of the repository.

## Makefile Commands

There are several commands available in the Makefile:

- `make build` - Build the binary
- `make build-admin` - Build the admin web (requires Node.js). It is embedded in the binary, so build it before `make build`
- `make build-all` - Build the admin web and the binary
- `make run` - Run the binary
- `make build-docker` - Build the docker image (it builds the admin web too)
- `make run-docker` - Run the docker image
- `make test` - Run the tests
- `make clean` - Clean the binary
- `make lint` - Run the linter
- `make hash text=plain_text_to_hash` - Generate a hash from a given `text`

## Configuration

You have to set the following environment variables:

- `MINIOIDC_ADDR` - The address to listen on (default: `:8000`)
- `MINIOIDC_CONFIG` - The path to the yaml configuration file

The configuration file is a yaml file with the following structure:

```yaml
name: My MiniOIDC
masterkey: ${MINIOIDC_MASTERKEY} # at least 32 characters
issuer: https://sso.example.com
audience: https://sso.example.com
require_mfa: true
reuse_refresh_tokens: false
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
- `use_in_grants` - Whether to store the codes and refresh tokens in the database (default: `false`)
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

The paths are relative to the working directory: if a template does not exist, minioidc does not start.

> In your templates, use `{{ basePath }}` to build the local URLs (e.g. `{{ basePath }}/static/styles.css`), so they work when the issuer has a path.

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

- The `masterkey` must have at least 32 characters.
- The cookies and the codes, refresh tokens and CSRF tokens issued by previous versions are no longer valid: the users log in again.
- PKCE `plain` is no longer supported (only `S256`).
- `email_verified` is `false` unless it is set in the users (or in `ldap.email_verified`).
- `phone_number` and `address` are returned with the `phone` and `address` scopes (not with `profile`), and `address` is a JSON object (`{"formatted": "..."}`).
- The endpoints are published under the path of the issuer.
- The MFA enrollments of previous versions (TOTP with SHA256) keep working. The new ones use SHA1, supported by every authenticator app.
- The SQLite databases are migrated on start up.

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
- `PrivateRSAKey *rsa.PrivateKey` or `PrivateRSAKeyFilepath string` - The signing key (if not set, a new random key will be generated)
- `PreviousRSAPublicKeys []*rsa.PublicKey` and `PreviousRSAKeyFilepaths []string` - The previous signing keys (key rotation)
- `UseHSTS`, `UseCSP`, `UseSecureCookie`, `UseForwardedHeaders`, `LogRequests bool` - The middlewares (default: `false`)
- `AccessTTL`, `RefreshTTL`, `SessionTTL`, `CodeTTL`, `CSRFTTL time.Duration` - The TTLs
- `BaseTemplateFilepath`, `LoginTemplateFilepath`, `MFACreateTemplateFilepath`, `MFAVerifyTemplateFilepath`, `LogoutTemplateFilepath string` - The templates
- `ClientStore`, `UserStore`, `GrantStore`, `SessionStore`, `MFACodeStore`, `UserBlockedStore`, `ClientAssertionStore` - Custom stores (default: in memory, or SQLite with `UseSQLite`)
- `Clients []Client` - The clients: `ID`, `SecretHash`, `Secret`, `RedirectURIs`, `PostLogoutRedirectURIs`, `TokenEndpointAuthMethod`, `JWKSURI`, `PublicKeyPaths` and `PublicKeys`
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

## Contributing


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

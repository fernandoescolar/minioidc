# minioidc

[![Go](https://img.shields.io/badge/go-1.26.3+-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

minioidc is a lightweight OpenID Connect (OIDC) / OAuth 2.0 authorization server designed to provide Single Sign-On (SSO) functionality for small or home networks. It is not a complete OIDC implementation, but covers the most common grant types and endpoints.

Supported grant types:

| Grant type | RFC |
|---|---|
| Authorization Code + PKCE | [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) |
| Implicit | [OpenID Connect Core §3.2](https://openid.net/specs/openid-connect-core-1_0.html) |
| Hybrid | [OpenID Connect Core §3.3](https://openid.net/specs/openid-connect-core-1_0.html) |
| Refresh Token | [RFC 6749 §6](https://datatracker.ietf.org/doc/html/rfc6749#section-6) |
| Client Credentials | [RFC 6749 §4.4](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4) |
| Resource Owner Password | [RFC 6749 §4.3](https://datatracker.ietf.org/doc/html/rfc6749#section-4.3) |
| Device Code | [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) |
| JWT Bearer | [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523) |

## Features

- **Simple and Lightweight** — designed to be a straightforward SSO solution for small or home networks.
- **All major OAuth 2.0 grant types** — including Device Code (RFC 8628) and JWT Bearer (RFC 7523).
- **OIDC Discovery + JWKS** — fully compliant `/.well-known/openid-configuration` and JWKS endpoint.
- **Token Revocation** — RFC 7009 revocation endpoint for access and refresh tokens.
- **RP-Initiated Logout** — OIDC end session endpoint with `post_logout_redirect_uri` support.
- **Introspection** — RFC 7662 token introspection endpoint.
- **PKCE enforcement** — required for public clients (no secret).
- **at_hash / c_hash** — correct computation in ID tokens for implicit and hybrid flows.
- **Client and User Configuration** — configure clients and users directly in the YAML file.
- **Flexible Data Storage** — in-memory (default) or SQLite v3 for grants, sessions and MFA.
- **LDAP Users** — plug in an LDAP directory as the user store.
- **MFA** — TOTP-based MFA (e.g. Google Authenticator / Authy) per user.
- **Customisable Templates** — override any HTML page with your own `html/template` files.
- **Secure by Default** — HSTS, CSP, secure cookies, forwarded-header support, all opt-in via config.

## Requirements

- Go 1.22 or later (for running from source or using as a library)
- Docker (optional, for the containerised setup)

## Installation

### From source

```bash
git clone https://github.com/fernandoescolar/minioidc.git
cd minioidc
make build          # produces ./minioidc binary
```

### Docker

```bash
make build-docker   # builds the image
make run-docker     # starts the container on :8000
```

### As a Go library

```bash
go get github.com/fernandoescolar/minioidc
```

## Getting Started

1. Copy the example configuration:

```bash
cp example.env .env
cp example1_config.yml config.yml   # simple in-memory setup
# or
cp example2_config.yml config.yml   # SQLite + LDAP setup
```

2. Edit `config.yml` to set your issuer, clients, and users (see [Configuration](#configuration)).

3. Run the server:

```bash
MINIOIDC_ADDR=:8000 MINIOIDC_CONFIG=config.yml ./minioidc
# or
make run
```

4. Visit [http://localhost:8000](http://localhost:8000) — the welcome page confirms the server is running.

5. The OIDC discovery document is available at:

```
http://localhost:8000/.well-known/openid-configuration
```

## Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/.well-known/openid-configuration` | GET | OIDC discovery document |
| `/.well-known/jwks.json` | GET | JSON Web Key Set |
| `/connect/authorize` | GET | Authorization endpoint |
| `/connect/token` | POST | Token endpoint |
| `/connect/userinfo` | GET / POST | Userinfo endpoint |
| `/connect/introspect` | POST | Token introspection (RFC 7662) |
| `/connect/revoke` | POST | Token revocation (RFC 7009) |
| `/connect/endsession` | GET / POST | RP-Initiated Logout |
| `/connect/deviceauthorization` | POST | Device authorization (RFC 8628) |
| `/connect/device` | GET / POST | Device activation page (user-facing) |
| `/login` | GET / POST | Login page |
| `/mfa/create` | GET / POST | MFA enrolment page |
| `/mfa/verify` | GET / POST | MFA verification page |

## Makefile Commands

| Command | Description |
|---|---|
| `make build` | Build the binary |
| `make run` | Run the binary |
| `make build-docker` | Build the Docker image |
| `make run-docker` | Run the Docker image |
| `make test` | Run all tests |
| `make clean` | Remove build artefacts |
| `make lint` | Run the linter |
| `make hash text=<plaintext>` | Generate a bcrypt hash for a password or client secret |

## Configuration

Set the following environment variables before starting the server:

| Variable | Default | Description |
|---|---|---|
| `MINIOIDC_ADDR` | `:8000` | Address and port to listen on |
| `MINIOIDC_CONFIG` | — | Path to the YAML configuration file (required) |

### Full configuration reference

```yaml
name: My MiniOIDC
masterkey: 12345678901234567890123456789012   # AES master key for internal encryption
issuer: http://example.com
audience: http://example.com
require_mfa: false
reuse_refresh_tokens: false
private_rsa_key_path: private_key.pem         # omit to generate a random key on startup

middlewares:
  hsts: true            # HTTP Strict Transport Security
  csp: true             # Content Security Policy
  secure_cookies: true  # Secure flag on session cookies
  forward_headers: true # Trust X-Forwarded-* headers (use behind a reverse proxy)
  log_requests: true    # Log every request with duration

ttl:
  access: 20        # Access token TTL in minutes (default 20)
  refresh: 129600   # Refresh token TTL in minutes (default 90 days)
  session: 129600   # Session TTL in minutes (default 90 days)
  code: 5           # Authorization / device code TTL in minutes (default 5)
  csrf: 5           # CSRF token TTL in minutes (default 5)

sqlite:
  filepath: db.sqlite3
  use_in_grants: true
  use_in_sessions: true
  use_in_mfa: true

ldap:
  server: localhost:389
  bind: uid=admin,cn=users,dc=example,dc=com
  password: password
  base_dn: dc=example,dc=com
  filter_dn: (&(uid={username})(objectClass=person))
  attributes:
    subject: uidNumber
    name: uid
    email: mail
    phone: phone
    address: address

templates:
  base: templates/base.html
  login: templates/login.html
  mfa_create: templates/mfa_create.html
  mfa_verify: templates/mfa_verify.html
  device: templates/device.html   # Device Code activation page

clients:
  - id: myclient
    secret_hash: $2a$06$L6/zALdtbkYajjHTZUW29ePBEb/hwhgjhXC4YpHANavvKDJl69ctK  # "secret"
    redirect_uris:
      - http://myapi.com/callback
  - id: publicclient
    secret_hash: ""   # public client — no secret, PKCE required
    redirect_uris:
      - http://myapp.com/callback

users:
  - subject: "1"
    email: user@mail.com
    email_verified: true
    preferred_username: user
    password_hash: $2a$06$03dduqc0lMbsb5go/l6RI.cRb03Hos9CMpgm5/yYuRsSQPHtrFwSq  # "password"
    phone: +1234567890
    address: 1 Main St. City, State 12345
    groups:
      - admin
```

**Root settings**

| Key | Default | Description |
|---|---|---|
| `issuer` | — | OIDC issuer URL (required) |
| `audience` | — | JWT audience (required) |
| `require_mfa` | `false` | Enforce TOTP MFA for all users |
| `reuse_refresh_tokens` | `false` | Allow refresh tokens to be used more than once |
| `private_rsa_key_path` | — | Path to a PEM-encoded RSA private key; a 2048-bit key is generated if omitted |

**`middlewares`**

| Key | Default | Description |
|---|---|---|
| `hsts` | `false` | Add `Strict-Transport-Security` header |
| `csp` | `false` | Add `Content-Security-Policy` header |
| `secure_cookies` | `false` | Mark session cookie as `Secure` |
| `forward_headers` | `false` | Trust `X-Forwarded-Proto` / `X-Forwarded-Host` |
| `log_requests` | `false` | Log each request with method, path, status and duration |

**`ttl`** — all values are in **minutes**

**`sqlite`** — omit the section entirely to use in-memory stores

**`ldap`** — if set, the `users` section is ignored

> Static assets (CSS, JS, images) go in the `static/` directory and are served at `/static/`.
> Reference them from templates as `<link rel="stylesheet" href="/static/styles.css">`.

Environment variable substitution is supported anywhere in the YAML:

```yaml
masterkey: ${MINIOIDC_MASTER_KEY}
ldap:
  password: $LDAP_PASSWORD
```

## Use in your projects

```go
package main

import (
	"log"
	"net/http"

	"github.com/fernandoescolar/minioidc/pkg/api"
)

func main() {
	builder := &api.Builder{
		Issuer:   "https://minioidc.example.com",
		Audience: "https://api.example.com",
		Clients: []api.Client{
			{
				ID:           "myclient",
				SecretHash:   "$2a$06$L6/zALdtbkYajjHTZUW29ePBEb/hwhgjhXC4YpHANavvKDJl69ctK", // "secret"
				RedirectURIs: []string{"https://api.example.com/callback"},
			},
		},
		Users: []api.User{
			{
				Subject:           "0000001",
				PreferredUsername: "user",
				PasswordHash:      "$2a$06$03dduqc0lMbsb5go/l6RI.cRb03Hos9CMpgm5/yYuRsSQPHtrFwSq", // "password"
			},
		},
	}

	minioidc, err := builder.Build()
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	handler := minioidc.Wrap(mux)

	log.Println("Listening on http://localhost:8000")
	if err := http.ListenAndServe(":8000", handler); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
```

### Builder fields

| Field | Type | Default | Description |
|---|---|---|---|
| `Name` | `string` | `"minioidc"` | Display name shown on login/device pages |
| `MasterKey` | `string` | random | AES key for internal encryption (auto-generated if empty) |
| `Issuer` | `string` | — | OIDC issuer URL **(required)** |
| `Audience` | `string` | — | JWT audience **(required)** |
| `RequireMFA` | `bool` | `false` | Enforce TOTP MFA for all users |
| `ReuseRefreshTokens` | `bool` | `false` | Allow reuse of refresh tokens |
| `PrivateRSAKey` | `*rsa.PrivateKey` | — | RSA private key (generated if neither key nor filepath is set) |
| `PrivateRSAKeyFilepath` | `string` | — | Path to a PEM RSA private key file |
| `UseHSTS` | `bool` | `false` | Enable HSTS middleware |
| `UseCSP` | `bool` | `false` | Enable CSP middleware |
| `UseSecureCookie` | `bool` | `false` | Set `Secure` flag on cookies |
| `UseForwardedHeaders` | `bool` | `false` | Trust `X-Forwarded-*` headers |
| `LogRequests` | `bool` | `false` | Log all HTTP requests |
| `AccessTTL` | `time.Duration` | 20 min | Access token lifetime |
| `RefreshTTL` | `time.Duration` | 90 days | Refresh token lifetime |
| `SessionTTL` | `time.Duration` | 90 days | Session cookie lifetime |
| `CodeTTL` | `time.Duration` | 5 min | Authorization / device code lifetime |
| `CSRFTTL` | `time.Duration` | 5 min | CSRF token lifetime |
| `BaseTemplateFilepath` | `string` | `templates/base.html` | Base layout template |
| `LoginTemplateFilepath` | `string` | `templates/login.html` | Login page template |
| `MFACreateTemplateFilepath` | `string` | `templates/mfa_create.html` | MFA enrolment template |
| `MFAVerifyTemplateFilepath` | `string` | `templates/mfa_verify.html` | MFA verification template |
| `DeviceTemplateFilepath` | `string` | `templates/device.html` | Device Code activation template |
| `ClientStore` | `domain.ClientStore` | in-memory | Custom client store implementation |
| `UserStore` | `domain.UserStore` | in-memory | Custom user store implementation |
| `GrantStore` | `domain.GrantStore` | in-memory | Custom grant store implementation |
| `SessionStore` | `domain.SessionStore` | in-memory | Custom session store implementation |
| `MFACodeStore` | `domain.MFACodeStore` | in-memory | Custom MFA code store implementation |
| `DeviceCodeStore` | `domain.DeviceCodeStore` | in-memory | Custom device code store implementation |
| `Clients` | `[]Client` | — | Seed clients |
| `Users` | `[]User` | — | Seed users |

### Builder methods

| Method | Description |
|---|---|
| `UseSQLite(filepath string, databases SqliteDatabases)` | Persist grants, sessions and/or MFA in a SQLite file. Flags: `Grants`, `Sessions`, `MFA`, `All`. |
| `UseLDAP(server string, config LDAPConfig)` | Use an LDAP directory as the user store. |

### LDAPConfig fields

| Field | Description |
|---|---|
| `Bind` | LDAP bind DN |
| `Password` | LDAP bind password |
| `BaseDN` | Base DN for user searches |
| `FilterDN` | Search filter; use `{username}` as placeholder |
| `SubjectAttribute` | Attribute mapped to `sub` claim |
| `NameAttribute` | Attribute mapped to `preferred_username` |
| `EmailAttribute` | Attribute mapped to `email` |
| `PhoneAttribute` | Attribute mapped to `phone_number` |
| `AddressAttribute` | Attribute mapped to `address` |

## Roadmap

- [x] OIDC Discovery endpoint with JWKS
- [x] Authorization endpoint
  - [x] Authorization Code with PKCE
  - [x] Implicit flow
  - [x] Hybrid flow
- [x] Device Code authorization endpoint (RFC 8628)
- [x] Token endpoint
  - [x] Refresh Token
  - [x] Client Credentials
  - [x] Password
  - [x] JWT Bearer (RFC 7523)
  - [x] Device Code (RFC 8628)
- [x] Userinfo endpoint
- [x] Introspection endpoint
- [x] Revocation endpoint (RFC 7009)
- [x] End session endpoint (RP-Initiated Logout)
- [x] CSRF protection
- [x] YAML config file with ENV variable substitution
- [x] SQLite database for grants, sessions and MFA
- [x] MFA with TOTP (e.g. Google Authenticator)
- [x] LDAP users integration
- [ ] MFA via email
- [ ] Change password
- [ ] Forgot password
- [ ] MFA management UI
- [ ] MongoDB store
- [ ] Groups / roles
- [ ] Management API

## Testing

Run the full test suite:

```bash
make test
# or
go test ./... -timeout 120s
```

Run only the integration tests:

```bash
go test ./tests/integration/... -v -timeout 120s
```

Run a specific subset:

```bash
go test ./tests/integration/... -run "Test_DeviceCode|Test_JWTBearer" -v
```

## Security

minioidc is intended for **small / home networks** and has not undergone a formal security audit. For production use, please review the following:

- Always run behind a TLS-terminating reverse proxy (nginx, Caddy, Traefik) and enable `secure_cookies: true` and `hsts: true`.
- Use a strong, random `masterkey` (32+ bytes) and keep it secret.
- Rotate the RSA private key periodically; store it outside the repository.
- Public clients (no `secret_hash`) **require PKCE** — this is enforced by the server.
- Refresh tokens and device codes are single-use by default.

To report a vulnerability, please open a GitHub issue marked **[SECURITY]** or contact the maintainer directly.

## Contributing

Contributions are welcome. Please:

1. Fork the repository and create a feature branch.
2. Add tests for any new functionality.
3. Run `make lint` and `make test` and ensure both pass.
4. Open a pull request with a clear description of the change.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

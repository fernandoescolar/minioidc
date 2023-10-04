# minioidc

minioidc is a lightweight OpenID Connect (OIDC) server designed to provide Single Sign-On (SSO) functionality for small or home networks. While not a complete OIDC implementation, minioidc currently supports the following grant types:

- *Authorization Code with PKCE*: Securely obtain an authorization code using Proof Key for Code Exchange (PKCE).
- *Refresh Token*: Extend the validity of access tokens using refresh tokens.

## Features

- **Simple and Lightweight**: minioidc is designed to be a straightforward solution for enabling SSO in small or home networks.
- **Client and User Configuration**: Easily configure client and user data directly in the YAML configuration file.
- **Flexible Data Storage**: Store grant and session data in memory or use a SQLite v3 database for more persistent storage.
- **LDAP Users Integration**: Use LDAP users to login.
- **MFA**: Require MFA for all users using TOTP App (e.g. Google Authenticator).
- **Secure by Default**: Enable HTTP Strict Transport Security (HSTS), Content Security Policy (CSP), secure cookies, and more with a single configuration option.

## Roadmap

The following features are planned for future releases:

- [x] OIDC Discovery
- [x] Authorization Code with PKCE
- [x] Refresh Token
- [x] CSRF
- [x] Yaml config file
- [x] ENV secrets inside yaml config file
- [x] Sqlite database for grants and sessions (and also for MFA)
- [x] MFA with TOTP App (e.g. Google Authenticator)
- [ ] MFA with email?
- [x] Ldap Users integration

## Getting Started

- You can create a docker image and run it with the following commands:

```bash
make build-docker && make run-docker
```

And then visit [http://localhost:8000](http://localhost:8000).

- You can also use the visual studio code launch configuration to run the server in debug mode.

- Or you can call the `make run` command to run the server directly.

## Makefile Commands

There are several commands available in the Makefile:

- `make build` - Build the binary
- `make run` - Run the binary
- `make build-docker` - Build the docker image
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
masterkey: 12345678901234567890123456789012
issuer: http://example.com
audience: http://example.com
require_mfa: true
reuse_refresh_tokens: false
private_rsa_key_path: private_key.pem
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
  login: templates/login2.html
  mfa_create: templates/mfa_create.html
  mfa_verify: templates/mfa_verify.html
clients:
  - id: myclient
    secret_hash: $2a$06$L6/zALdtbkYajjHTZUW29ePBEb/hwhgjhXC4YpHANavvKDJl69ctK # secret
    redirect_uris:
     - http://myapi.com/callback
users:
  - subject: 1
    email: use@mail.com
    email_verified: true
    preferred_username: user
    password_hash: $2a$06$03dduqc0lMbsb5go/l6RI.cRb03Hos9CMpgm5/yYuRsSQPHtrFwSq # password
    phone: +1234567890
    address: 1 Main St. City, State 12345
    groups:
      - admin
```

In the root section, you can configure the following settings:

- `issuer` - The OIDC issuer
- `audience` - The OIDC audience
- `require_mfa` - Whether to require MFA for all users (default: `false`)
- `reuse_refresh_tokens` - Whether to allow re-use refresh tokens (default: `false`)
- `private_rsa_key_path` - The path to the private RSA key (if not set, a new random key will be generated)

In the `middlewares` section, you can activate the following middlewares:

- `hsts` - Whether to enable HTTP Strict Transport Security (HSTS) (default: `false`)
- `csp` - Whether to enable Content Security Policy (CSP) (default: `false`)
- `secure_cookies` - Whether to enable secure cookies (default: `false`)
- `forward_headers` - Whether to forward headers (default: `false`)
- `log_requests` - Whether to log requests (default: `false`)

In the `ttl` section, you can configure the following TTLs:

- `access` - The access token TTL in minutes (default: `20`)
- `refresh` - The refresh token TTL in minutes (default: `129600`, 90 days)
- `session` - The session TTL in minutes (default: `129600`, 90 days)
- `code` - The authorization code TTL in minutes (default: `5`)
- `csrf` - The CSRF token TTL in minutes (default: `5`)

In the `sqlite` section, you can configure the following SQLite settings:

- `filepath` - The path to the SQLite database file. It is mandatory if `use_in_grants` or `use_in_sessions` is set to `true`.
- `use_in_grants` - Whether to use the SQLite database for storing grant data (default: `false`)
- `use_in_sessions` - Whether to use the SQLite database for storing session data (default: `false`)
- `use_in_mfa` - Whether to use the SQLite database for storing MFA data (default: `false`)

In the `ldap` section, you can configure the LDAP user store settings:

- `server` - The LDAP server address
- `bind` - The LDAP bind DN
- `password` - The LDAP bind password
- `base_dn` - The LDAP base DN
- `filter_dn` - The LDAP filter DN
- `attributes` - The LDAP attributes to use for each user property
- `attributes.subject` - The LDAP attribute to use for the user subject
- `attributes.name` - The LDAP attribute to use for the user name
- `attributes.email` - The LDAP attribute to use for the user email
- `attributes.phone` - The LDAP attribute to use for the user phone
- `attributes.address` - The LDAP attribute to use for the user address

> If you use LDAP users, you can not configure the `users` section in the yaml configuration file.

In the `templates` section, you can configure the following html/templates:

- `base` - The base template
- `login` - The login page template
- `mfa_create` - The MFA create page template
- `mfa_verify` - The MFA verify page template

> you can add your static files (like css, js, images, ...) in the `static` folder and use them in your templates (e.g. `<link rel="stylesheet" href="/static/css/style.css">`

Seed data is provided in the `clients` and `users` sections. In the `clients` section, you can create the OIDC clients to use in the auth challenge. Each client has the following properties:

- `id` - The client ID
- `secret_hash` - The client secret hash (use the `make hash` command to generate a hash)
- `redirect_uris` - The list of allowed redirect URIs

In the `users` section, you can create the users to login. Each user has the following properties:

- `subject` - The user subject
- `email` - The user email
- `email_verified` - Whether the user email is verified
- `preferred_username` - The user preferred username (the username used for login)
- `password_hash` - The user password hash (use the `make hash` command to generate a hash)
- `phone` - The user phone number
- `address` - The user address
- `groups` - The list of user groups

The yaml configuration file can also reference environment variables. You can use the following syntax to use environment variables in your yaml configuration file:

```yaml
value1: ${ENV_VAR}
value2: $OTHER_ENV_VAR
```

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
		Audience: "https://api.example.com",
		Issuer:   "https://minioidc.example.com",
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

	minioidc, err := builder.Build(config)
	if err != nil {
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

- `Name string` - Set the OIDC name (default: `minioidc`)
- `MasterKey string` - Set the OIDC master key use to encrypt and decrypt internal data (if not set, a new random key will be generated)
- `Audience string` - Set the OIDC audience (it is MANADATORY)
- `Issuer string` - Set the OIDC issuer (it is MANADATORY)
- `RequireMFA bool` - Set whether to require MFA for all users (default: `false`)
- `ReuseRefreshTokens bool` - Set whether to allow re-use refresh tokens (default: `false`)
- `UseHSTS bool` - Set whether to enable HTTP Strict Transport Security (HSTS) (default: `false`)
- `UseCSP bool` - Set whether to enable Content Security Policy (CSP) (default: `false`)
- `UseSecureCookie bool` - Set whether to enable secure cookies (default: `false`)
- `UseForwardedHeaders bool` - Set whether to forward headers (default: `false`)
- `LogRequests bool` - Set whether to log requests (default: `false`)
- `Clients []Client` - Set the OIDC clients
- `Users []User` - Set the OIDC users
- `PrivateKey *rsa.PrivateKey` - Set the OIDC private key
- `PrivateKeyFile string` - Set the OIDC private key from a file
- `AccessTTL time.Duration` - Set the access token TTL
- `RefreshTTL time.Duration` - Set the refresh token TTL
- `SessionTTL time.Duration` - Set the session TTL
- `CodeTTL time.Duration` - Set the authorization code TTL
- `CSRFTTL time.Duration` - Set the CSRF token TTL
- `ClientStore ClientStore` - Set the client store
- `UserStore UserStore` - Set the user store
- `GrantStore GrantStore` - Set the grant store
- `SessionStore SessionStore` - Set the session store
- `MFAStore MFAStore` - Set the MFA store
- `BaseTemplate string` - Set the base template
- `LoginTemplate string` - Set the login template
- `MFACreateTemplate string` - Set the MFA create template
- `MFAVerifyTemplate string` - Set the MFA verify template

And the builder has the following methods:

- `UseSQLite(string, SqliteDatabases)` - Set the SQLite database file path and databases to use (flags: `NoSqliteDatabases`, `Grants`, `Sessions` or `MFA`)
- `UseLDAP(string, LDAPConfig)` - Set the LDAP server address and LDAP config to use

The `LDAPConfig` struct has the following fields:

- `Bind string` - The LDAP bind DN
- `Password string` - The LDAP bind password
- `BaseDN string` - The LDAP base DN
- `FilterDN string` - The LDAP filter DN
- `SubjectAttribute string` - The LDAP attribute to use for the user subject
- `NameAttribute string` - The LDAP attribute to use for the user name
- `EmailAttribute string` - The LDAP attribute to use for the user email
- `PhoneAttribute string` - The LDAP attribute to use for the user phone
- `AddressAttribute string` - The LDAP attribute to use for the user address

## Contributing


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details



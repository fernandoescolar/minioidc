# minioidc

minioidc is a lightweight OpenID Connect (OIDC) server designed to provide Single Sign-On (SSO) functionality for small or home networks. While not a complete OIDC implementation, minioidc currently supports the following grant types:

- *Authorization Code with PKCE*: Securely obtain an authorization code using Proof Key for Code Exchange (PKCE).
- *Refresh Token*: Extend the validity of access tokens using refresh tokens.

## Features

- **Simple and Lightweight**: minioidc is designed to be a straightforward solution for enabling SSO in small or home networks.
- **Client and User Configuration**: Easily configure client and user data directly in the YAML configuration file.
- **Flexible Data Storage**: Store grant and session data in memory or use a SQLite v3 database for more persistent storage.

## Getting Started

- You can create a docker image and run it with the following commands:

```bash
make build-docker && make run-docker
```

And then visit [http://localhost:8080](http://localhost:8080).

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

- `MINIOIDC_ADDR` - The address to listen on (default: `:8080`)
- `MINIOIDC_CONFIG` - The path to the yaml configuration file

The configuration file is a yaml file with the following structure:

```yaml
issuer: http://example.com
audience: http://example.com
private_rsa_key_path: private_key.pem
ttl:
  access: 20 # minutes
  refresh: 129600 # 90 days
  session: 129600 # 90 days
  code: 5 # minutes
sqlite:
  filepath: db.sqlite3
  use_in_grants: true
  use_in_sessions: true
templates:
  login: templates/login2.html
clients:
  - id: myclient
    secret_hash: $2a$06$L6/zALdtbkYajjHTZUW29ePBEb/hwhgjhXC4YpHANavvKDJl69ctK # secret
    redirect_uris:
     - http://localhost:8080/callback
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
- `private_rsa_key_path` - The path to the private RSA key (if not set, a new random key will be generated)

In the `ttl` section, you can configure the following TTLs:

- `access` - The access token TTL in minutes (default: `20`)
- `refresh` - The refresh token TTL in minutes (default: `129600`, 90 days)
- `session` - The session TTL in minutes (default: `129600`, 90 days)
- `code` - The authorization code TTL in minutes (default: `5`)

In the `sqlite` section, you can configure the following SQLite settings:

- `filepath` - The path to the SQLite database file. It is mandatory if `use_in_grants` or `use_in_sessions` is set to `true`.
- `use_in_grants` - Whether to use the SQLite database for storing grant data (default: `false`)
- `use_in_sessions` - Whether to use the SQLite database for storing session data (default: `false`)

In the `templates` section, you can configure the following html/templates:

- `login` - The login page template

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
	builder := api.NewBuilder().
		WithAudience("https://api.example.com").
		WithIssuer("https://minioidc.example.com").
		WithClients([]api.Client{
			{
				ID:           "myclient",
				SecretHash:   "$2a$06$L6/zALdtbkYajjHTZUW29ePBEb/hwhgjhXC4YpHANavvKDJl69ctK", // secret
				RedirectURIs: []string{"https://api.example.com/callback"},
			},
		}).
		WithUsers([]api.User{
			{
				Subject:           "0000001",
				PreferredUsername: "user",
				PasswordHash:      "$2a$06$03dduqc0lMbsb5go/l6RI.cRb03Hos9CMpgm5/yYuRsSQPHtrFwSq", // password
			},
		})

	minioidc, err := builder.Build(config)
	if err != nil {
		log.Fatal(err)
	}

	handler := http.NewServeMux()
	minioidc.Add(handler)

	log.Printf("Listening http://localhost:8000")
	err = http.ListenAndServe(":8000", handler)
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
```

The builder has the following methods:

- `WithAudience(string)` - Set the OIDC audience
- `WithIssuer(string)` - Set the OIDC issuer
- `WithClients([]Client)` - Set the OIDC clients
- `WithUsers([]User)` - Set the OIDC users
- `WithPrivateKey(*rsa.PrivateKey)` - Set the OIDC private key
- `WithPrivateKeyFile(string)` - Set the OIDC private key from a file
- `WithAccessTTL(int)` - Set the access token TTL in minutes
- `WithRefreshTTL(int)` - Set the refresh token TTL in minutes
- `WithSessionTTL(int)` - Set the session TTL in minutes
- `WithCodeTTL(int)` - Set the authorization code TTL in minutes
- `WithClientStore(ClientStore)` - Set the client store
- `WithUserStore(UserStore)` - Set the user store
- `WithGrantStore(GrantStore)` - Set the grant store
- `WithSessionStore(SessionStore)` - Set the session store
- `WithLoginTemplate(string)` - Set the login template
- `WithSQLite(string, SqliteDatabases)` - Set the SQLite database file path and databases to use (`NoSqliteDatabases`, `OnlyInGrants`, `OnlyInSessions` or `InGrantsAndSessions`)

## Contributing


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details



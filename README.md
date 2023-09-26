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
server:
  issuer: http://example.com
  audience: http://example.com
  private_rsa_key_path: private_key.pem
  access_ttl: 20 # minutes
  refresh_ttl: 129600 # 90 days
  session_ttl: 129600 # 90 days
  code_ttl: 5 # minutes
  sqlite_filepath: db.sqlite3
  use_sqlite_grant_store: true
  use_sqlite_session_store: true
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

In the `server` section, you can configure the following settings:

- `issuer` - The OIDC issuer
- `audience` - The OIDC audience
- `private_rsa_key_path` - The path to the private RSA key (if not set, a new random key will be generated)
- `access_ttl` - The access token TTL in minutes (default: `20`)
- `refresh_ttl` - The refresh token TTL in minutes (default: `129600`, 90 days)
- `session_ttl` - The session TTL in minutes (default: `129600`, 90 days)
- `code_ttl` - The authorization code TTL in minutes (default: `5`)
- `sqlite_filepath` - The path to the SQLite database file. It is mandatory if `use_sqlite_grant_store` or `use_sqlite_session_store` is set to `true`.
- `use_sqlite_grant_store` - Whether to use the SQLite database for storing grant data (default: `false`)
- `use_sqlite_session_store` - Whether to use the SQLite database for storing session data (default: `false`)

In the `templates` section, you can configure the following html/templates:

- `login` - The login page template

> you can add your static files (like css, js, images, ...) in the `static` folder and use them in your templates (e.g. `<link rel="stylesheet" href="/static/css/style.css">`

In the `clients` section, you can create the OIDC clients to use in the auth challenge. Each client has the following properties:

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

	"github.com/fernandoescolar/minioidc/api"
	"github.com/fernandoescolar/minioidc/pkg/builder"
)

func main() {
	builder := builder.NewYamlBuilder("configure.yaml")
	config := builder.Build()
	minioidc, err := api.NewMinioidc(config)
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


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details



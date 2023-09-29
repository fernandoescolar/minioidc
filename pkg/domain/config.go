package domain

import (
	"time"

	"github.com/fernandoescolar/minioidc/pkg/cryptography"
)

type Config struct {
	// is the display name of server.
	Name string
	// is the key to internal encryption in the server.
	MasterKey string

	// is the issuer set in JWTs.
	Issuer string
	// is the audience set in JWTs.
	Audience string
	// is the path to the private RSA key used to sign JWTs.
	Keypair *cryptography.Keypair

	// is the time to live of access tokens.
	AccessTTL time.Duration
	// is the time to live of refresh tokens.
	RefreshTTL time.Duration
	// is the time to live of sessions.
	SessionTTL time.Duration
	// is the time to live of authorization codes.
	CodeTTL time.Duration

	// is the store used to save clients.
	ClientStore ClientStore
	// is the store used to save grants.
	GrantStore GrantStore
	// is the store used to save sessions.
	SessionStore SessionStore
	// is the store used to save users.
	UserStore UserStore

	// the filepath of the login template.
	LoginTemplateFilepath string
}

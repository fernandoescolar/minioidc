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
	// if true, the server will require MFA for all users.
	RequireMFA bool
	// if true, allows re-use refresh tokens in different request
	ReuseRefreshTokens bool
	// is the path to the private RSA key used to sign JWTs.
	Keypair *cryptography.Keypair

	// if true, the server will use HSTS.
	UseHSTS bool
	// if true, the server will use CSP.
	UseCSP bool
	// if true, the server will use secure cookies.
	UseSecureCookie bool
	// if true, the server will use forwarded headers.
	UseForwardedHeaders bool
	// if true, the server will log when a request starts and ends.
	LogRequests bool

	// is the time to live of access tokens.
	AccessTTL time.Duration
	// is the time to live of refresh tokens.
	RefreshTTL time.Duration
	// is the time to live of sessions.
	SessionTTL time.Duration
	// is the time to live of authorization codes.
	CodeTTL time.Duration
	// is the time to live of CSRF tokens.
	CSRFTTL time.Duration

	// is the store used to save clients.
	ClientStore ClientStore
	// is the store used to save grants.
	GrantStore GrantStore
	// is the store used to save sessions.
	SessionStore SessionStore
	// is the store used to save users.
	UserStore UserStore
	// is the store used to save MFA codes.
	MFACodeStore MFACodeStore

	// is the filepath of the base template.
	BaseTemplateFilepath string
	// the filepath of the login template.
	LoginTemplateFilepath string
	// the filepath of the MFA template.
	MFACreateTemplateFilepath string
	// the filepath of the MFA template.
	MFAVerifyTemplateFilepath string
}

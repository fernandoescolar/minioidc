package domain

import (
	"time"

	"github.com/fernandoescolar/minioidc/pkg/cryptography"
)

type Config struct {
	// is the display name of server.
	Name string
	// ConfigFilepath is the configuration file (empty without it).
	ConfigFilepath string
	// DataDir is the data directory of the default configuration (without a file).
	DataDir string
	// SqliteFilepath is the database (empty without it).
	SqliteFilepath string
	// is the key to internal encryption in the server.
	MasterKey string

	// is the issuer set in JWTs.
	Issuer string
	// is the path of the issuer URL without trailing slash (e.g. "/auth"). All the endpoints are under it.
	BasePath string
	// is the audience set in JWTs.
	Audience string
	// if true, the server will require MFA for all users.
	RequireMFA bool
	// if true, allows re-use refresh tokens in different request
	ReuseRefreshTokens bool
	// if true, the clients with the "implicit" grant type can use the implicit
	// and hybrid flows. They are discouraged (RFC 9700): disabled by default.
	AllowImplicitFlow bool
	// if true, the clients with the "password" grant type can use the resource
	// owner password credentials grant. It is discouraged (RFC 9700): disabled by default.
	AllowPasswordGrant bool
	// is the RSA keypair used to sign JWTs (with the previous public keys to verify them).
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
	// is the store used to save user blocked.
	UserBlockedStore UserBlockedStore
	// is the store used to save MFA codes.
	MFACodeStore MFACodeStore
	// is the store used to save the passkeys.
	PasskeyStore PasskeyStore
	// is the store used to save the state of the accounts (disabled, locked…).
	UserStateStore UserStateStore
	// is the store used to save the password reset links.
	PasswordResetStore PasswordResetStore
	// is the store of the definitions of the groups (their descriptions).
	GroupStore GroupStore
	// is the store of the activity log (the logins, the changes of the
	// accounts and the actions of the administrators).
	EventStore EventStore
	// Events writes the activity log. The router creates it with its clock.
	Events *Recorder
	// EventRetention is how long the events are kept.
	EventRetention time.Duration
	// is the store used to save the used client assertions (jti).
	ClientAssertionStore ClientAssertionStore
	// is the store used to save the device codes (RFC 8628).
	DeviceCodeStore DeviceCodeStore

	// is the configuration of the LDAP server with the users (nil if it is disabled).
	LDAPServer *LDAPServerConfig

	// if true, the admin web is served at <issuer>/admin/ to the members of AdminGroup.
	AdminEnabled bool
	// is the group of the administrators.
	AdminGroup string

	// is the filepath of the base template.
	BaseTemplateFilepath string
	// the filepath of the login template.
	LoginTemplateFilepath string
	// the filepath of the MFA template.
	MFACreateTemplateFilepath string
	// the filepath of the MFA template.
	MFAVerifyTemplateFilepath string
	// the filepath of the logout template.
	LogoutTemplateFilepath string
	// the filepath of the error template.
	ErrorTemplateFilepath string
	// the filepath of the device activation template.
	DeviceTemplateFilepath string
	// the filepath of the user profile template.
	ProfileTemplateFilepath string
	// the filepath of the change-password template.
	ProfilePasswordTemplateFilepath string
	// the filepath of the MFA management template.
	ProfileMFATemplateFilepath string
	// the filepath of the onboarding template (the first administrator).
	SetupTemplateFilepath string
	// the filepath of the passkeys management template.
	ProfilePasskeysTemplateFilepath string
	// the filepath of the template of the password reset links.
	ResetPasswordTemplateFilepath string

	// if true, the users can sign in with passkeys (WebAuthn).
	PasskeysEnabled bool

	// is the code to create the first administrator when there are no users.
	// Empty to generate a random one (it is written in the log).
	SetupCode string
}

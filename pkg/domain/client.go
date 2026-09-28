package domain

import (
	"crypto"
	"crypto/subtle"
	"fmt"

	"github.com/fernandoescolar/minioidc/pkg/cryptography"
)

// Client authentication methods at the token, revocation and introspection endpoints
const (
	AuthMethodClientSecretBasic = "client_secret_basic"
	AuthMethodClientSecretPost  = "client_secret_post"
	AuthMethodClientSecretJWT   = "client_secret_jwt"
	AuthMethodPrivateKeyJWT     = "private_key_jwt"
	AuthMethodNone              = "none"

	// MinClientSecretJWTLength is the minimum length of the secret used to sign
	// client_secret_jwt assertions (RFC 7518 section 3.2: a key of 256 bits for HS256)
	MinClientSecretJWTLength = 32
)

type ClientStore interface {
	NewClient(data ClientData) (Client, error)
	GetClientByID(id string) (Client, error)
}

// ClientAdminStore is implemented by the client stores that can be managed from the admin web
type ClientAdminStore interface {
	ClientStore
	ListClients() ([]ClientData, error)
	UpdateClient(data ClientData) error
	DeleteClient(id string) error
}

// ClientData are the properties of a registered client
type ClientData struct {
	ID string
	// SecretHash is the bcrypt hash of the secret (client_secret_basic and client_secret_post)
	SecretHash string
	// Secret is the plain secret. It is only used by client_secret_jwt, because
	// the assertions are signed with HMAC and they cannot be verified with a hash.
	Secret                 string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	// TokenEndpointAuthMethod is the only authentication method allowed. If it
	// is empty, client_secret_basic and client_secret_post are allowed when the
	// client has a secret hash, and none (public client) otherwise.
	TokenEndpointAuthMethod string
	// JWKSURI and PublicKeys are the keys of the private_key_jwt assertions
	JWKSURI    string
	PublicKeys []crypto.PublicKey
}

type Client interface {
	// ClientID is the unique ID for this Client
	ClientID() string

	// Data returns the registration of the client
	Data() ClientData

	// IsPublic returns true if the client cannot authenticate (e.g. SPA or mobile apps).
	// Public clients must use PKCE.
	IsPublic() bool

	// AuthMethodAllowed returns true if the client can authenticate with the method
	AuthMethodAllowed(method string) bool

	// ClientSecretIsValid returns true if the passed secret is valid for
	ClientSecretIsValid(string) bool

	// RedirectURLIsValid returns true if the passed redirect URL is valid for
	RedirectURLIsValid(string) bool

	// PostLogoutRedirectURLIsValid returns true if the passed URL is allowed after logout
	PostLogoutRedirectURLIsValid(string) bool
}

// ValidateClientData checks that the client has the credentials its authentication method needs
func ValidateClientData(data ClientData) error {
	if data.ID == "" {
		return fmt.Errorf("client id is required")
	}

	switch data.TokenEndpointAuthMethod {
	case "":
		if data.Secret != "" || data.JWKSURI != "" || len(data.PublicKeys) > 0 {
			return fmt.Errorf("client %s: token_endpoint_auth_method is required to use a plain secret or public keys", data.ID)
		}
	case AuthMethodClientSecretBasic, AuthMethodClientSecretPost:
		if data.SecretHash == "" {
			return fmt.Errorf("client %s: secret_hash is required by %s", data.ID, data.TokenEndpointAuthMethod)
		}
	case AuthMethodClientSecretJWT:
		if len(data.Secret) < MinClientSecretJWTLength {
			return fmt.Errorf("client %s: a secret of at least %d characters is required by client_secret_jwt", data.ID, MinClientSecretJWTLength)
		}
	case AuthMethodPrivateKeyJWT:
		if data.JWKSURI == "" && len(data.PublicKeys) == 0 {
			return fmt.Errorf("client %s: jwks_uri or public keys are required by private_key_jwt", data.ID)
		}
	case AuthMethodNone:
		if data.SecretHash != "" || data.Secret != "" {
			return fmt.Errorf("client %s: public clients cannot have a secret", data.ID)
		}
	default:
		return fmt.Errorf("client %s: unsupported token_endpoint_auth_method %s", data.ID, data.TokenEndpointAuthMethod)
	}

	return nil
}

func NewClient(data ClientData) Client {
	return &client{data: data}
}

// Client is a default implementation of the Client interface
type client struct {
	data ClientData
}

// ClientID is the unique ID for this Client
func (c *client) ClientID() string {
	return c.data.ID
}

func (c *client) Data() ClientData {
	return c.data
}

// IsPublic returns true if the client has no credentials
func (c *client) IsPublic() bool {
	method := c.data.TokenEndpointAuthMethod
	return method == AuthMethodNone || (method == "" && c.data.SecretHash == "")
}

func (c *client) AuthMethodAllowed(method string) bool {
	switch {
	case c.data.TokenEndpointAuthMethod != "":
		return method == c.data.TokenEndpointAuthMethod
	case c.IsPublic():
		return method == AuthMethodNone
	default:
		return method == AuthMethodClientSecretBasic || method == AuthMethodClientSecretPost
	}
}

// ClientSecretIsValid returns true if the passed secret is valid for
// this Client
func (c *client) ClientSecretIsValid(secret string) bool {
	if secret == "" {
		return false
	}

	if c.data.SecretHash != "" {
		return cryptography.CheckPasswordHash(secret, c.data.SecretHash)
	}

	return c.data.Secret != "" && subtle.ConstantTimeCompare([]byte(secret), []byte(c.data.Secret)) == 1
}

// RedirectURLIsValid returns true if the passed redirect URL is valid for
// this Client
func (c *client) RedirectURLIsValid(url string) bool {
	return contains(c.data.RedirectURIs, url)
}

// PostLogoutRedirectURLIsValid returns true if the passed URL is registered
// as post logout redirect URL for this Client
func (c *client) PostLogoutRedirectURLIsValid(url string) bool {
	return contains(c.data.PostLogoutRedirectURIs, url)
}

func contains(list []string, value string) bool {
	for _, element := range list {
		if element == value {
			return true
		}
	}

	return false
}

package domain

import (
	"time"

	"github.com/fernandoescolar/minioidc/pkg/cryptography"
)

type ClientStore interface {
	NewClient(id string, secret string, redirectUris []string) (Client, error)
	GetClientByID(id string) (Client, error)
}

type Client interface {
	// ClientID is the unique ID for this Client
	ClientID() string

	// ClientSecretIsValid returns true if the passed secret is valid for
	ClientSecretIsValid(string) bool

	// RedirectURLIsValid returns true if the passed redirect URL is valid for
	RedirectURLIsValid(string) bool

	// ScopesAreValid returns true if the passed scopes are valid for
	ScopesAreValid(scopes []string) bool

	// ResponseTypeIsValid returns true if the passed response type is valid for
	ResponseTypeIsValid(responseType string) bool

	// GetAudiences returns the audiences for this client
	GetAudiences() []string

	// GetAuthorizationCodeTTL returns the TTL for the authorization code
	GetAuthorizationCodeTTL() *time.Duration

	// GetAccessTokenTTL returns the TTL for the access_token
	GetAccessTokenTTL() *time.Duration

	// GetIDTokenTTL returns the TTL for the id_token
	GetIDTokenTTL() *time.Duration

	// GetRefreshTokenTTL returns the TTL for the refresh_token
	GetRefreshTokenTTL() *time.Duration
}

func NewClient(id, secret string, redirectUrls []string) Client {
	return &client{
		id:           id,
		secretHash:   secret,
		redirectUrls: redirectUrls,
	}
}

// Client is a default implementation of the Client interface
type client struct {
	id           string
	secretHash   string
	redirectUrls []string
}

// ClientID is the unique ID for this Client
func (c *client) ClientID() string {
	return c.id
}

// ClientSecretIsValid returns true if the passed secret is valid for
// this Client
func (c *client) ClientSecretIsValid(secret string) bool {
	return cryptography.CheckPasswordHash(secret, c.secretHash)
}

// RedirectURLIsValid returns true if the passed redirect URL is valid for
// this Client
func (c *client) RedirectURLIsValid(url string) bool {
	for _, u := range c.redirectUrls {
		if u == url {
			return true
		}
	}
	return false
}

// ScopesAreValid returns true if the passed scopes are valid for
// this Client
func (c *client) ScopesAreValid(scopes []string) bool {
	return true
}

// ResponseTypeIsValid returns true if the passed response type is valid for
// this Client
func (c *client) ResponseTypeIsValid(responseType string) bool {
	return true
}

// GetAudiences returns the audiences for this client
func (c *client) GetAudiences() []string {
	return []string{c.id}
}

// GetAuthorizationCodeTTL returns the TTL for the authorization code
func (c *client) GetAuthorizationCodeTTL() *time.Duration {
	return nil
}

// GetAccessTokenTTL returns the TTL for the access_token
func (c *client) GetAccessTokenTTL() *time.Duration {
	return nil
}

// GetIDTokenTTL returns the TTL for the id_token
func (c *client) GetIDTokenTTL() *time.Duration {
	return nil
}

// GetRefreshTokenTTL returns the TTL for the refresh_token
func (c *client) GetRefreshTokenTTL() *time.Duration {
	return nil
}

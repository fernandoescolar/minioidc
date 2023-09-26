package domain

import (
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

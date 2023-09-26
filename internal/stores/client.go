package stores

import (
	"errors"
	"sync"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type miniClient struct {
	id           string
	secretHash   string
	redirectUrls []string
}

type miniClientStore struct {
	sync.RWMutex
	Store map[string]*miniClient
}

// NewClientStore initializes the ClientStore for this server
func NewClientStore() domain.ClientStore {
	return &miniClientStore{
		Store: make(map[string]*miniClient),
	}
}

// NewClient creates a new Client
func (cs *miniClientStore) NewClient(id string, secretHash string, redirectUris []string) (domain.Client, error) {
	client := &miniClient{
		id:           id,
		secretHash:   secretHash,
		redirectUrls: redirectUris,
	}

	cs.Lock()
	defer cs.Unlock()
	cs.Store[client.id] = client

	return client.toClient()
}

// GetClientByID looks up the Client
func (cs *miniClientStore) GetClientByID(id string) (domain.Client, error) {
	cs.RLock()
	defer cs.RUnlock()

	client, ok := cs.Store[id]
	if !ok {
		return nil, errors.New("client not found")
	}

	return client.toClient()
}

func (c *miniClient) toClient() (domain.Client, error) {
	return domain.NewClient(c.id, c.secretHash, c.redirectUrls), nil
}

package stores

import (
	"errors"
	"sync"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type miniClientStore struct {
	sync.Map
}

// NewClientStore initializes the ClientStore for this server
func NewClientStore() domain.ClientStore {
	return &miniClientStore{}
}

// NewClient creates a new Client
func (cs *miniClientStore) NewClient(data domain.ClientData) (domain.Client, error) {
	if err := domain.ValidateClientData(data); err != nil {
		return nil, err
	}

	cs.Store(data.ID, data)
	return domain.NewClient(data), nil
}

// GetClientByID looks up the Client
func (cs *miniClientStore) GetClientByID(id string) (domain.Client, error) {
	v, ok := cs.Load(id)
	if !ok {
		return nil, errors.New("client not found")
	}

	return domain.NewClient(v.(domain.ClientData)), nil
}

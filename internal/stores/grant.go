package stores

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type miniGrantStore struct {
	mu           sync.Mutex
	grants       map[string]*domain.GrantData
	clientIDs    map[string]string
	sessionIDs   map[string]string
	clientStore  domain.ClientStore
	sessionStore domain.SessionStore
}

// NewGrantStore initializes the GrantStore for this server
func NewGrantStore(clientStore domain.ClientStore, sessionStore domain.SessionStore) domain.GrantStore {
	return &miniGrantStore{
		grants:       make(map[string]*domain.GrantData),
		clientIDs:    make(map[string]string),
		sessionIDs:   make(map[string]string),
		clientStore:  clientStore,
		sessionStore: sessionStore,
	}
}

func (gs *miniGrantStore) NewCodeGrant(id string, client domain.Client, session domain.Session, expiresAt time.Time, scopes []string, nonce string, codeChallenge, codeChallengeMethod, redirectURI string) (domain.Grant, error) {
	return gs.store(&domain.GrantData{
		ID:                  id,
		FamilyID:            id,
		GrantType:           domain.GrantTypeCode,
		ExpiresAt:           expiresAt,
		Scopes:              scopes,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		RedirectURI:         redirectURI,
	}, client, session)
}

func (gs *miniGrantStore) NewRefreshTokenGrant(id, familyID string, client domain.Client, session domain.Session, expiresAt time.Time, scopes []string) (domain.Grant, error) {
	return gs.store(&domain.GrantData{
		ID:        id,
		FamilyID:  familyID,
		GrantType: domain.GrantTypeRefresh,
		ExpiresAt: expiresAt,
		Scopes:    scopes,
	}, client, session)
}

func (gs *miniGrantStore) store(data *domain.GrantData, client domain.Client, session domain.Session) (domain.Grant, error) {
	gs.mu.Lock()
	gs.grants[data.ID] = data
	gs.clientIDs[data.ID] = client.ClientID()
	gs.sessionIDs[data.ID] = session.ID()
	gs.mu.Unlock()

	return domain.NewGrant(*data, client, session), nil
}

func (gs *miniGrantStore) GetGrantByIDAndType(id string, grantType domain.GrantType) (domain.Grant, error) {
	gs.mu.Lock()
	data, ok := gs.grants[id]
	var copied domain.GrantData
	if ok {
		copied = *data
	}
	clientID, sessionID := gs.clientIDs[id], gs.sessionIDs[id]
	gs.mu.Unlock()

	if !ok || copied.GrantType != grantType {
		return nil, errors.New("grant not found")
	}

	session, err := gs.sessionStore.GetSessionByID(sessionID)
	if err != nil {
		return nil, fmt.Errorf("GetGrantByIDAndType: %w", err)
	}

	client, err := gs.clientStore.GetClientByID(clientID)
	if err != nil {
		return nil, fmt.Errorf("GetGrantByIDAndType: %w", err)
	}

	return domain.NewGrant(copied, client, session), nil
}

func (gs *miniGrantStore) Grant(id string) error {
	gs.mu.Lock()
	defer gs.mu.Unlock()

	data, ok := gs.grants[id]
	if !ok || data.Used {
		return errors.New("grant not found")
	}

	data.Used = true
	return nil
}

func (gs *miniGrantStore) RevokeFamily(familyID string) error {
	gs.mu.Lock()
	defer gs.mu.Unlock()

	for id, data := range gs.grants {
		if data.FamilyID == familyID {
			gs.delete(id)
		}
	}

	return nil
}

func (gs *miniGrantStore) RevokeClient(clientID string) error {
	gs.mu.Lock()
	defer gs.mu.Unlock()

	for id, grantClientID := range gs.clientIDs {
		if grantClientID == clientID {
			gs.delete(id)
		}
	}

	return nil
}

func (gs *miniGrantStore) CleanExpired() {
	gs.mu.Lock()
	defer gs.mu.Unlock()

	now := time.Now()
	for id, data := range gs.grants {
		if data.ExpiresAt.Before(now) {
			gs.delete(id)
		}
	}
}

func (gs *miniGrantStore) delete(id string) {
	delete(gs.grants, id)
	delete(gs.clientIDs, id)
	delete(gs.sessionIDs, id)
}

package stores

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

type miniGrantStore struct {
	sync.RWMutex
	store        map[string]*miniGrant
	clientStore  domain.ClientStore
	sessionStore domain.SessionStore
}

type miniGrant struct {
	id                  string
	grantType           domain.GrantType
	sessionID           string
	clientID            string
	expiresAt           time.Time
	scopes              string
	nonce               string
	codeChallenge       string
	codeChallengeMethod string
}

// NewSessionStore initializes the SessionStore for this server
func NewGrantStore(clientStore domain.ClientStore, sessionStore domain.SessionStore) domain.GrantStore {
	return &miniGrantStore{
		store:        make(map[string]*miniGrant),
		clientStore:  clientStore,
		sessionStore: sessionStore,
	}
}

func (gs *miniGrantStore) NewCodeGrant(client domain.Client, session domain.Session, expiresAt time.Time, scopes []string, nonce string, codeChallenge, codeChallengeMethod string) (domain.Grant, error) {
	scopesStr := strings.Join(scopes, " ")
	grant := &miniGrant{
		id:                  gs.createNewGrantID(),
		grantType:           domain.GrantTypeCode,
		clientID:            client.ClientID(),
		sessionID:           session.ID(),
		expiresAt:           expiresAt,
		scopes:              scopesStr,
		nonce:               nonce,
		codeChallenge:       codeChallenge,
		codeChallengeMethod: codeChallengeMethod,
	}

	gs.Lock()
	defer gs.Unlock()
	gs.store[grant.id] = grant

	return gs.ToGrant(grant)
}

func (gs *miniGrantStore) NewRefreshTokenGrant(client domain.Client, session domain.Session, expiresAt time.Time, scopes []string) (domain.Grant, error) {
	scopesStr := strings.Join(scopes, " ")
	grant := &miniGrant{
		id:        gs.createNewGrantID(),
		grantType: domain.GrantTypeRefresh,
		clientID:  client.ClientID(),
		sessionID: session.ID(),
		expiresAt: expiresAt,
		scopes:    scopesStr,
	}

	gs.Lock()
	defer gs.Unlock()
	gs.store[grant.id] = grant

	return gs.ToGrant(grant)
}

func (gs *miniGrantStore) GetGrantByID(grantID string) (domain.Grant, error) {
	gs.RLock()
	defer gs.RUnlock()

	grant, ok := gs.store[grantID]
	if !ok {
		return nil, errors.New("grant not found")
	}

	return gs.ToGrant(grant)
}

func (gs *miniGrantStore) GetGrantByToken(token *jwt.Token) (domain.Grant, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	grantID := claims["jti"].(string)
	return gs.GetGrantByID(grantID)
}

func (gs *miniGrantStore) GetGrantByIDAndType(id string, grantType domain.GrantType) (domain.Grant, error) {
	grant, err := gs.GetGrantByID(id)
	if err != nil {
		return nil, err
	}

	if grant.GrantType() != grantType {
		return nil, errors.New("grant not found")
	}

	return grant, nil
}

func (gs *miniGrantStore) Grant(id string) error {
	gs.Lock()
	defer gs.Unlock()

	delete(gs.store, id)

	return nil
}

func (gs *miniGrantStore) CleanExpired() {
	gs.Lock()
	defer gs.Unlock()

	for id, grant := range gs.store {
		if grant.expiresAt.Before(time.Now()) {
			delete(gs.store, id)
		}
	}
}

func (gs *miniGrantStore) ToGrant(grant *miniGrant) (domain.Grant, error) {
	session, err := gs.sessionStore.GetSessionByID(grant.sessionID)
	if err != nil {
		return nil, err
	}

	client, err := gs.clientStore.GetClientByID(grant.clientID)
	if err != nil {
		return nil, err
	}

	scopes := strings.Split(grant.scopes, " ")
	return domain.NewGrant(grant.id, grant.grantType, client, session, grant.expiresAt, scopes, grant.nonce, grant.codeChallenge, grant.codeChallengeMethod), nil
}

func (gs *miniGrantStore) createNewGrantID() string {
	id := uuid.New().String() + uuid.New().String()
	return strings.ReplaceAll(id, "-", "")
}

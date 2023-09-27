package stores

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

type sqlGrantStore struct {
	db           *sql.DB
	clientStore  domain.ClientStore
	sessionStore domain.SessionStore
}

// NewSqliteGrantStore initializes the GrantStore for this server
func NewSqliteGrantStore(db *sql.DB, clientStore domain.ClientStore, sessionStore domain.SessionStore) domain.GrantStore {
	return &sqlGrantStore{
		db:           db,
		clientStore:  clientStore,
		sessionStore: sessionStore,
	}
}

// NewCodeGrant creates a new Grant for a User
func (gs *sqlGrantStore) NewCodeGrant(client domain.Client, session domain.Session, expiresAt time.Time, scopes []string, nonce string, codeChallenge, codeChallengeMethod string) (domain.Grant, error) {
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

	_, err := gs.db.Exec("INSERT INTO grants VALUES(?,?,?,?,?,?,?,?,?);", grant.id, grant.grantType, grant.clientID, grant.sessionID, grant.expiresAt, scopesStr, grant.nonce, grant.codeChallenge, grant.codeChallengeMethod)

	if err != nil {
		return nil, fmt.Errorf("NewCodeGrant: %w", err)
	}

	return gs.ToGrant(grant)
}

// NewRefreshTokenGrant creates a new Grant for a User
func (gs *sqlGrantStore) NewRefreshTokenGrant(client domain.Client, session domain.Session, expiresAt time.Time, scopes []string) (domain.Grant, error) {
	scopesStr := strings.Join(scopes, " ")
	grant := &miniGrant{
		id:        gs.createNewGrantID(),
		grantType: domain.GrantTypeRefresh,
		clientID:  client.ClientID(),
		sessionID: session.ID(),
		expiresAt: expiresAt,
		scopes:    scopesStr,
	}

	_, err := gs.db.Exec("INSERT INTO grants VALUES(?,?,?,?,?,?,?,?,?);", grant.id, grant.grantType, grant.clientID, grant.sessionID, grant.expiresAt, scopesStr, grant.nonce, grant.codeChallenge, grant.codeChallengeMethod)
	if err != nil {
		return nil, fmt.Errorf("NewRefreshTokenGrant: %w", err)
	}

	return gs.ToGrant(grant)
}

// GetGrantByID looks up the Grant
func (gs *sqlGrantStore) GetGrantByID(id string) (domain.Grant, error) {
	grant := &miniGrant{}
	row := gs.db.QueryRow("SELECT id, grantType, clientID, sessionID, expiresAt, scopes, nonce, codeChallenge, codeChallengeMethod FROM grants WHERE id = ?;", id)
	err := row.Scan(&grant.id, &grant.grantType, &grant.clientID, &grant.sessionID, &grant.expiresAt, &grant.scopes, &grant.nonce, &grant.codeChallenge, &grant.codeChallengeMethod)
	if err != nil {
		return nil, fmt.Errorf("GetGrantByID: %w", err)
	}

	return gs.ToGrant(grant)
}

func (gs *sqlGrantStore) GetGrantByToken(token *jwt.Token) (domain.Grant, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	grantID := claims["jti"].(string)
	return gs.GetGrantByID(grantID)
}

func (gs *sqlGrantStore) GetGrantByIDAndType(id string, grantType domain.GrantType) (domain.Grant, error) {
	grant, err := gs.GetGrantByID(id)
	if err != nil {
		return nil, err
	}

	if grant.GrantType() != grantType {
		return nil, errors.New("grant not found")
	}

	return grant, nil
}

// DeleteGrantByID deletes a grant
func (gs *sqlGrantStore) Grant(id string) error {
	_, err := gs.db.Exec("DELETE FROM grants WHERE id = ?;", id)
	return err
}

// CleanExpired deletes all expired grants
func (gs *sqlGrantStore) CleanExpired() {
	_, err := gs.db.Exec("DELETE FROM grants WHERE expiresAt < ?;", time.Now())
	if err != nil {
		log.Println("WRN Grants CleanExpired: %w", err)
	}
}

func (gs *sqlGrantStore) ToGrant(grant *miniGrant) (domain.Grant, error) {
	session, err := gs.sessionStore.GetSessionByID(grant.sessionID)
	if err != nil {
		return nil, fmt.Errorf("ToGrant: %w", err)
	}

	client, err := gs.clientStore.GetClientByID(grant.clientID)
	if err != nil {
		return nil, fmt.Errorf("ToGrant: %w", err)
	}

	scopes := strings.Split(grant.scopes, " ")
	return domain.NewGrant(grant.id, grant.grantType, client, session, grant.expiresAt, scopes, grant.nonce, grant.codeChallenge, grant.codeChallengeMethod), nil
}

func (gs *sqlGrantStore) createNewGrantID() string {
	id := uuid.New().String() + uuid.New().String()
	return strings.ReplaceAll(id, "-", "")
}

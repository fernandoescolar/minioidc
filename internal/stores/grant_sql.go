package stores

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
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
func (gs *sqlGrantStore) NewCodeGrant(id string, client domain.Client, session domain.Session, expiresAt time.Time, scopes []string, nonce string, codeChallenge, codeChallengeMethod, redirectURI string) (domain.Grant, error) {
	return gs.insert(domain.GrantData{
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

// NewRefreshTokenGrant creates a new Grant for a User
func (gs *sqlGrantStore) NewRefreshTokenGrant(id, familyID string, client domain.Client, session domain.Session, expiresAt time.Time, scopes []string) (domain.Grant, error) {
	return gs.insert(domain.GrantData{
		ID:        id,
		FamilyID:  familyID,
		GrantType: domain.GrantTypeRefresh,
		ExpiresAt: expiresAt,
		Scopes:    scopes,
	}, client, session)
}

func (gs *sqlGrantStore) insert(data domain.GrantData, client domain.Client, session domain.Session) (domain.Grant, error) {
	_, err := gs.db.Exec(
		"INSERT INTO grants(id, familyID, used, grantType, clientID, sessionID, issuedAt, expiresAt, scopes, nonce, codeChallenge, codeChallengeMethod, redirectURI) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?);",
		data.ID, data.FamilyID, false, data.GrantType, client.ClientID(), session.ID(), time.Now(), data.ExpiresAt, strings.Join(data.Scopes, " "),
		data.Nonce, data.CodeChallenge, data.CodeChallengeMethod, data.RedirectURI,
	)
	if err != nil {
		return nil, fmt.Errorf("insert grant: %w", err)
	}

	return domain.NewGrant(data, client, session), nil
}

// GetGrantByIDAndType looks up the Grant
func (gs *sqlGrantStore) GetGrantByIDAndType(id string, grantType domain.GrantType) (domain.Grant, error) {
	var (
		data                               domain.GrantData
		clientID, sessionID, scopes        string
		familyID, nonce, challenge, method sql.NullString
		redirectURI                        sql.NullString
		used                               sql.NullBool
	)

	row := gs.db.QueryRow("SELECT id, familyID, used, grantType, clientID, sessionID, expiresAt, scopes, nonce, codeChallenge, codeChallengeMethod, redirectURI FROM grants WHERE id = ?;", id)
	err := row.Scan(&data.ID, &familyID, &used, &data.GrantType, &clientID, &sessionID, &data.ExpiresAt, &scopes, &nonce, &challenge, &method, &redirectURI)
	if err != nil {
		return nil, fmt.Errorf("GetGrantByIDAndType: %w", err)
	}

	if data.GrantType != grantType {
		return nil, errors.New("grant not found")
	}

	// the nullable columns were added by migrations
	data.FamilyID = familyID.String
	if data.FamilyID == "" {
		data.FamilyID = data.ID
	}
	data.Used = used.Bool
	data.Scopes = strings.Split(scopes, " ")
	data.Nonce = nonce.String
	data.CodeChallenge = challenge.String
	data.CodeChallengeMethod = method.String
	data.RedirectURI = redirectURI.String

	session, err := gs.sessionStore.GetSessionByID(sessionID)
	if err != nil {
		return nil, fmt.Errorf("GetGrantByIDAndType: %w", err)
	}

	client, err := gs.clientStore.GetClientByID(clientID)
	if err != nil {
		return nil, fmt.Errorf("GetGrantByIDAndType: %w", err)
	}

	return domain.NewGrant(data, client, session), nil
}

// Grant marks a grant as used
func (gs *sqlGrantStore) Grant(id string) error {
	r, err := gs.db.Exec("UPDATE grants SET used = 1 WHERE id = ? AND (used IS NULL OR used = 0);", id)
	if err != nil {
		return fmt.Errorf("Grant: %w", err)
	}

	rows, err := r.RowsAffected()
	if err != nil {
		return fmt.Errorf("Grant: %w", err)
	}

	if rows != 1 {
		return errors.New("grant not found")
	}

	return nil
}

// RevokeFamily deletes all the grants of a family
func (gs *sqlGrantStore) RevokeFamily(familyID string) error {
	_, err := gs.db.Exec("DELETE FROM grants WHERE familyID = ? OR id = ?;", familyID, familyID)
	if err != nil {
		return fmt.Errorf("RevokeFamily: %w", err)
	}

	return nil
}

// RevokeClient deletes all the grants of a client
func (gs *sqlGrantStore) RevokeClient(clientID string) error {
	if _, err := gs.db.Exec("DELETE FROM grants WHERE clientID = ?;", clientID); err != nil {
		return fmt.Errorf("RevokeClient: %w", err)
	}

	return nil
}

// CleanExpired deletes all expired grants. The dates are compared in Go: they
// are stored as text with their time zone, so SQL cannot compare them.
func (gs *sqlGrantStore) CleanExpired() {
	if err := deleteExpired(gs.db, "grants", time.Now()); err != nil {
		log.Printf("WRN grants CleanExpired: %v", err)
	}
}

package stores

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type sqlSessionStore struct {
	db        *sql.DB
	userStore domain.UserStore
}

// NewSqliteSessionStore initializes the SessionStore for this server
func NewSqliteSessionStore(db *sql.DB, userStore domain.UserStore) domain.SessionStore {
	return &sqlSessionStore{
		db:        db,
		userStore: userStore,
	}
}

// NewSession creates a new Session for a User
func (ss *sqlSessionStore) NewSession(sessionID string, user domain.User, expiresAt time.Time) (domain.Session, error) {
	session := &miniSession{
		id:        sessionID,
		userID:    user.ID(),
		expiresAt: expiresAt,
	}

	_, err := ss.db.Exec("INSERT INTO sessions VALUES(?,?,?);", session.id, session.userID, session.expiresAt)
	if err != nil {
		return nil, fmt.Errorf("NewSession: %w", err)
	}

	return ss.Session(session)
}

// GetSessionByID looks up the Session
func (ss *sqlSessionStore) GetSessionByID(id string) (domain.Session, error) {
	session := &miniSession{}
	row := ss.db.QueryRow("SELECT id, userID, expiresAt FROM sessions WHERE id = ?;", id)
	err := row.Scan(&session.id, &session.userID, &session.expiresAt)
	if err != nil {
		return nil, fmt.Errorf("GetSessionByID: %w", err)
	}

	return ss.Session(session)
}

// DeleteUserSessions deletes all sessions for a user
func (ss *sqlSessionStore) DeleteUserSessions(userID string) {
	_, err := ss.db.Exec("DELETE FROM sessions WHERE userID = ?;", userID)
	if err != nil {
		log.Println("WRN DeleteUserSessions: %w", err)
	}
}

// CleanExpired deletes all expired sessions
func (ss *sqlSessionStore) CleanExpired() {
	_, err := ss.db.Exec("DELETE FROM sessions WHERE expiresAt < ?;", time.Now())
	if err != nil {
		log.Println("WRN Session CleanExpired: %w", err)
	}
}

func (ss *sqlSessionStore) Session(session *miniSession) (domain.Session, error) {
	user, err := ss.userStore.GetUserByID(session.userID)
	if err != nil {
		return nil, fmt.Errorf("Session: %w", err)
	}

	return domain.NewSession(session.id, user, session.expiresAt), nil
}

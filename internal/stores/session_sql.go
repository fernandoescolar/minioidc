package stores

import (
	"database/sql"
	"errors"
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
func (ss *sqlSessionStore) NewSession(sessionID string, user domain.User, authTime, expiresAt time.Time, requireMFA bool) (domain.Session, error) {
	session := &miniSession{
		id:         sessionID,
		userID:     user.ID(),
		requireMFA: requireMFA,
		authTime:   authTime,
		expiresAt:  expiresAt,
	}

	_, err := ss.db.Exec("INSERT INTO sessions(id, userID, requireMFA, expiresAt, authTime) VALUES(?,?,?,?,?);", session.id, session.userID, session.requireMFA, session.expiresAt, session.authTime)
	if err != nil {
		return nil, fmt.Errorf("NewSession: %w", err)
	}

	return ss.Session(session)
}

// GetSessionByID looks up the Session
func (ss *sqlSessionStore) GetSessionByID(id string) (domain.Session, error) {
	session := &miniSession{}
	var authTime sql.NullTime
	var mfaVerified sql.NullBool
	row := ss.db.QueryRow("SELECT id, userID, expiresAt, requireMFA, authTime, mfaVerified FROM sessions WHERE id = ?;", id)
	err := row.Scan(&session.id, &session.userID, &session.expiresAt, &session.requireMFA, &authTime, &mfaVerified)
	if err != nil {
		return nil, fmt.Errorf("GetSessionByID: %w", err)
	}

	// sessions created before the authTime column existed
	session.authTime = authTime.Time
	session.mfaVerified = mfaVerified.Bool

	return ss.Session(session)
}

// VerifyMFA checks if the Session has MFA enabled
func (ss *sqlSessionStore) VerifyMFA(id string) error {
	r, err := ss.db.Exec("UPDATE sessions SET requireMFA = 0, mfaVerified = 1 WHERE id = ?;", id)
	if err != nil {
		return fmt.Errorf("VerifyMFA: %w", err)
	}

	rows, err := r.RowsAffected()
	if err != nil {
		return fmt.Errorf("VerifyMFA: %w", err)
	}

	if rows != 1 {
		return errors.New("VerifyMFA: session not found")
	}

	return nil
}

// UpdateTTL updates the TTL for a Session
func (ss *sqlSessionStore) UpdateTTL(id string, expiresAt time.Time) error {
	r, err := ss.db.Exec("UPDATE sessions SET expiresAt = ? WHERE id = ?;", expiresAt, id)
	if err != nil {
		return fmt.Errorf("UpdateTTL: %w", err)
	}

	rows, err := r.RowsAffected()
	if err != nil {
		return fmt.Errorf("UpdateTTL: %w", err)
	}

	if rows != 1 {
		return errors.New("UpdateTTL: session not found")
	}

	return nil
}

// DeleteSession deletes a session
func (ss *sqlSessionStore) DeleteSession(id string) error {
	r, err := ss.db.Exec("DELETE FROM sessions WHERE id = ?;", id)
	if err != nil {
		return fmt.Errorf("DeleteSession: %w", err)
	}

	rows, err := r.RowsAffected()
	if err != nil {
		return fmt.Errorf("DeleteSession: %w", err)
	}

	if rows != 1 {
		return errors.New("DeleteSession: session not found")
	}

	return nil
}

// DeleteUserSessions deletes all sessions for a user
func (ss *sqlSessionStore) DeleteUserSessions(userID string) {
	_, err := ss.db.Exec("DELETE FROM sessions WHERE userID = ?;", userID)
	if err != nil {
		log.Println("WRN DeleteUserSessions: %w", err)
	}
}

// ListUserSessions returns the sessions of a user that have not expired
func (ss *sqlSessionStore) ListUserSessions(userID string, now time.Time) ([]domain.Session, error) {
	rows, err := ss.db.Query("SELECT id FROM sessions WHERE userID = ?;", userID)
	if err != nil {
		return nil, fmt.Errorf("ListUserSessions: %w", err)
	}

	// the IDs are read before loading the sessions: there is only one SQLite connection
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, fmt.Errorf("ListUserSessions: %w", err)
		}

		ids = append(ids, id)
	}

	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("ListUserSessions: %w", err)
	}

	sessions := make([]domain.Session, 0, len(ids))
	for _, id := range ids {
		session, err := ss.GetSessionByID(id)
		if err != nil {
			return nil, err
		}

		if !session.HasExpired(now) {
			sessions = append(sessions, session)
		}
	}

	return sessions, nil
}

// DeleteAllSessions deletes all the sessions
func (ss *sqlSessionStore) DeleteAllSessions() error {
	if _, err := ss.db.Exec("DELETE FROM sessions;"); err != nil {
		return fmt.Errorf("DeleteAllSessions: %w", err)
	}

	return nil
}

// CleanExpired deletes all expired sessions. The dates are compared in Go: they
// are stored as text with their time zone, so SQL cannot compare them.
func (ss *sqlSessionStore) CleanExpired() {
	if err := deleteExpired(ss.db, "sessions", time.Now()); err != nil {
		log.Printf("WRN sessions CleanExpired: %v", err)
	}
}

func (ss *sqlSessionStore) Session(session *miniSession) (domain.Session, error) {
	user, err := ss.userStore.GetUserByID(session.userID)
	if err != nil {
		return nil, fmt.Errorf("Session: %w", err)
	}

	return domain.NewSession(session.id, user, session.requireMFA, session.mfaVerified, session.authTime, session.expiresAt), nil
}

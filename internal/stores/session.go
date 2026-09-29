package stores

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// SessionStore manages our Session objects
type miniSessionStore struct {
	sync.Map
	userStore domain.UserStore
}

type miniSession struct {
	id          string
	userID      string
	requireMFA  bool
	mfaVerified bool
	authTime    time.Time
	expiresAt   time.Time
}

// NewSessionStore initializes the SessionStore for this server
func NewSessionStore(userStore domain.UserStore) domain.SessionStore {
	return &miniSessionStore{
		userStore: userStore,
	}
}

// NewSession creates a new Session for a User
func (ss *miniSessionStore) NewSession(sessionID string, user domain.User, authTime, expiresAt time.Time, requireMFA bool) (domain.Session, error) {
	session := &miniSession{
		id:         sessionID,
		userID:     user.ID(),
		requireMFA: requireMFA,
		authTime:   authTime,
		expiresAt:  expiresAt,
	}

	ss.Store(sessionID, session)
	return ss.Session(session)
}

// GetSessionByID looks up the Session
func (ss *miniSessionStore) GetSessionByID(id string) (domain.Session, error) {
	v, ok := ss.Load(id)
	if !ok {
		return nil, errors.New("session not found")
	}

	session := v.(*miniSession)
	return ss.Session(session)
}

// VerifyMFA checks if the Session has MFA enabled
func (ss *miniSessionStore) VerifyMFA(id string) error {
	v, ok := ss.Load(id)
	if !ok {
		return errors.New("session not found")
	}

	// copy on write: the stored sessions are read concurrently
	session := *v.(*miniSession)
	session.requireMFA = false
	session.mfaVerified = true
	ss.Store(id, &session)

	return nil
}

// UpdateTTL updates the TTL for a Session
func (ss *miniSessionStore) UpdateTTL(id string, expiresAt time.Time) error {
	v, ok := ss.Load(id)
	if !ok {
		return errors.New("session not found")
	}

	session := *v.(*miniSession)
	session.expiresAt = expiresAt
	ss.Store(id, &session)

	return nil
}

// DeleteSession removes a Session
func (ss *miniSessionStore) DeleteSession(id string) error {
	if _, loaded := ss.LoadAndDelete(id); !loaded {
		return errors.New("session not found")
	}

	return nil
}

// DeleteUserSessions removes all Sessions for a User
func (ss *miniSessionStore) DeleteUserSessions(userID string) {
	ss.Range(func(k, v interface{}) bool {
		session := v.(*miniSession)
		if session.userID == userID {
			ss.Delete(k)
		}
		return true
	})
}

// ListUserSessions returns the Sessions of a User that have not expired
func (ss *miniSessionStore) ListUserSessions(userID string, now time.Time) ([]domain.Session, error) {
	var sessions []*miniSession
	ss.Range(func(_, v interface{}) bool {
		session := v.(*miniSession)
		if session.userID == userID && !now.After(session.expiresAt) {
			sessions = append(sessions, session)
		}
		return true
	})

	result := make([]domain.Session, 0, len(sessions))
	for _, session := range sessions {
		s, err := ss.Session(session)
		if err != nil {
			return nil, err
		}

		result = append(result, s)
	}

	return result, nil
}

// DeleteAllSessions removes all the Sessions
func (ss *miniSessionStore) DeleteAllSessions() error {
	ss.Range(func(k, _ interface{}) bool {
		ss.Delete(k)
		return true
	})

	return nil
}

// CleanExpired removes all expired Sessions
func (ss *miniSessionStore) CleanExpired() {
	ss.Range(func(k, v interface{}) bool {
		session := v.(*miniSession)
		if session.expiresAt.Before(time.Now()) {
			ss.Delete(k)
		}
		return true
	})
}

func (ss *miniSessionStore) Session(session *miniSession) (domain.Session, error) {
	user, err := ss.userStore.GetUserByID(session.userID)
	if err != nil {
		return nil, fmt.Errorf("Session: %w", err)
	}

	return domain.NewSession(session.id, user, session.requireMFA, session.mfaVerified, session.authTime, session.expiresAt), nil
}

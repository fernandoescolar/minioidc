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
	id         string
	userID     string
	requireMFA bool
	expiresAt  time.Time
}

// NewSessionStore initializes the SessionStore for this server
func NewSessionStore(userStore domain.UserStore) domain.SessionStore {
	return &miniSessionStore{
		userStore: userStore,
	}
}

// NewSession creates a new Session for a User
func (ss *miniSessionStore) NewSession(sessionID string, user domain.User, expiresAt time.Time, requireMFA bool) (domain.Session, error) {
	session := &miniSession{
		id:         sessionID,
		userID:     user.ID(),
		requireMFA: requireMFA,
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

	session := v.(*miniSession)
	session.requireMFA = false
	ss.Store(id, session)

	return nil
}

// UpdateTTL updates the TTL for a Session
func (ss *miniSessionStore) UpdateTTL(id string, expiresAt time.Time) error {
	v, ok := ss.Load(id)
	if !ok {
		return errors.New("session not found")
	}

	session := v.(*miniSession)
	session.expiresAt = expiresAt
	ss.Store(id, session)

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

	return domain.NewSession(session.id, user, session.requireMFA, session.expiresAt), nil
}

package stores

import (
	"errors"
	"sync"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// SessionStore manages our Session objects
type miniSessionStore struct {
	sync.RWMutex
	store     map[string]*miniSession
	userStore domain.UserStore
}

type miniSession struct {
	id        string
	userID    string
	expiresAt time.Time
}

// NewSessionStore initializes the SessionStore for this server
func NewSessionStore(userStore domain.UserStore) domain.SessionStore {
	return &miniSessionStore{
		store:     make(map[string]*miniSession),
		userStore: userStore,
	}
}

// NewSession creates a new Session for a User
func (ss *miniSessionStore) NewSession(sessionID string, user domain.User, expiresAt time.Time) (domain.Session, error) {
	session := &miniSession{
		id:        sessionID,
		userID:    user.ID(),
		expiresAt: expiresAt,
	}

	ss.Lock()
	defer ss.Unlock()
	ss.store[sessionID] = session

	return ss.ToSession(session)
}

// GetSessionByID looks up the Session
func (ss *miniSessionStore) GetSessionByID(id string) (domain.Session, error) {
	ss.RLock()
	defer ss.RUnlock()

	session, ok := ss.store[id]
	if !ok {
		return nil, errors.New("session not found")
	}
	return ss.ToSession(session)
}

func (ss *miniSessionStore) DeleteUserSessions(userID string) {
	ss.Lock()
	defer ss.Unlock()

	for id, session := range ss.store {
		if session.userID == userID {
			delete(ss.store, id)
		}
	}
}

func (ss *miniSessionStore) CleanExpired() {
	ss.Lock()
	defer ss.Unlock()

	for id, session := range ss.store {
		if session.expiresAt.Before(time.Now()) {
			delete(ss.store, id)
		}
	}
}

func (ss *miniSessionStore) ToSession(session *miniSession) (domain.Session, error) {
	user, err := ss.userStore.GetUserByID(session.userID)
	if err != nil {
		return nil, err
	}

	return domain.NewSession(session.id, user, session.expiresAt), nil
}

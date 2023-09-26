package domain

import (
	"time"
)

type SessionStore interface {
	NewSession(sessionID string, user User, expiresAt time.Time) (Session, error)
	GetSessionByID(id string) (Session, error)
	DeleteUserSessions(userID string)
	CleanExpired()
}

type Session interface {
	ID() string
	User() User
	HasExpired() bool
}

type session struct {
	id        string
	user      User
	expiresAt time.Time
}

func NewSession(sessionID string, user User, expiresAt time.Time) Session {
	return Session(&session{
		id:        sessionID,
		user:      user,
		expiresAt: expiresAt,
	})
}

func (s *session) ID() string {
	return s.id
}

func (s *session) User() User {
	return s.user
}

func (s *session) HasExpired() bool {
	return time.Now().After(s.expiresAt)
}

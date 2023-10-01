package domain

import (
	"time"
)

type SessionStore interface {
	NewSession(sessionID string, user User, expiresAt time.Time, mfaRequired bool) (Session, error)
	GetSessionByID(id string) (Session, error)
	VerifyMFA(sessionID string) error
	UpdateTTL(sessionID string, expiresAt time.Time) error
	DeleteUserSessions(userID string)
	CleanExpired()
}

type Session interface {
	ID() string
	User() User
	MFARequired() bool
	HasExpired() bool
}

type session struct {
	id         string
	user       User
	requireMFA bool
	expiresAt  time.Time
}

func NewSession(sessionID string, user User, requireMFA bool, expiresAt time.Time) Session {
	return Session(&session{
		id:         sessionID,
		user:       user,
		requireMFA: requireMFA,
		expiresAt:  expiresAt,
	})
}

func (s *session) ID() string {
	return s.id
}

func (s *session) User() User {
	return s.user
}

func (s *session) MFARequired() bool {
	return s.requireMFA
}

func (s *session) HasExpired() bool {
	return time.Now().After(s.expiresAt)
}

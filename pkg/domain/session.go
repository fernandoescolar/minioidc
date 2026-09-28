package domain

import (
	"time"
)

type SessionStore interface {
	NewSession(sessionID string, user User, authTime, expiresAt time.Time, mfaRequired bool) (Session, error)
	GetSessionByID(id string) (Session, error)
	VerifyMFA(sessionID string) error
	UpdateTTL(sessionID string, expiresAt time.Time) error
	DeleteSession(sessionID string) error
	DeleteUserSessions(userID string)
	// ListUserSessions returns the sessions of a user that have not expired
	ListUserSessions(userID string, now time.Time) ([]Session, error)
	// DeleteAllSessions logs out all the users
	DeleteAllSessions() error
	CleanExpired()
}

type Session interface {
	ID() string
	User() User
	MFARequired() bool
	AuthTime() time.Time
	ExpiresAt() time.Time
	// AuthMethods are the authentication methods used (RFC 8176 amr values)
	AuthMethods() []string
	HasExpired(now time.Time) bool
}

type session struct {
	id          string
	user        User
	requireMFA  bool
	mfaVerified bool
	authTime    time.Time
	expiresAt   time.Time
}

func NewSession(sessionID string, user User, requireMFA, mfaVerified bool, authTime, expiresAt time.Time) Session {
	return Session(&session{
		id:          sessionID,
		user:        user,
		requireMFA:  requireMFA,
		mfaVerified: mfaVerified,
		authTime:    authTime,
		expiresAt:   expiresAt,
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

func (s *session) AuthTime() time.Time {
	return s.authTime
}

func (s *session) ExpiresAt() time.Time {
	return s.expiresAt
}

func (s *session) AuthMethods() []string {
	if s.mfaVerified {
		return []string{"pwd", "otp", "mfa"}
	}

	return []string{"pwd"}
}

func (s *session) HasExpired(now time.Time) bool {
	return now.After(s.expiresAt)
}

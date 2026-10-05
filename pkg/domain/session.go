package domain

import (
	"time"
)

type SessionStore interface {
	NewSession(sessionID string, user User, authTime, expiresAt time.Time, mfaRequired bool) (Session, error)
	// NewPasskeySession creates a session authenticated with a passkey: it is a
	// multi-factor authentication, so the MFA is verified
	NewPasskeySession(sessionID string, user User, authTime, expiresAt time.Time) (Session, error)
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
	// Passkey is true if the user signed in with a passkey
	Passkey() bool
	HasExpired(now time.Time) bool
}

type session struct {
	id          string
	user        User
	requireMFA  bool
	mfaVerified bool
	passkey     bool
	authTime    time.Time
	expiresAt   time.Time
}

// NewPasskeySession is a session authenticated with a passkey (with its MFA verified)
func NewPasskeySession(sessionID string, user User, authTime, expiresAt time.Time) Session {
	return Session(&session{
		id:          sessionID,
		user:        user,
		mfaVerified: true,
		passkey:     true,
		authTime:    authTime,
		expiresAt:   expiresAt,
	})
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

func (s *session) Passkey() bool {
	return s.passkey
}

func (s *session) AuthMethods() []string {
	if s.passkey {
		// the proof of possession of a key, with the user verification
		// (biometrics or PIN) of the authenticator
		return []string{"hwk", "user", "mfa"}
	}

	if s.mfaVerified {
		return []string{"pwd", "otp", "mfa"}
	}

	return []string{"pwd"}
}

func (s *session) HasExpired(now time.Time) bool {
	return now.After(s.expiresAt)
}

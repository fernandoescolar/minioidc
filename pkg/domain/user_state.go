package domain

import (
	"errors"
	"time"
)

var (
	// ErrAccountDisabled means that an administrator has disabled the account
	ErrAccountDisabled = errors.New("the account is disabled")
	// ErrAccountLocked means that an administrator has locked the account
	ErrAccountLocked = errors.New("the account is locked")
	// ErrPasswordChangeRequired means that the password is temporary: the
	// user must change it before using it outside the login page
	ErrPasswordChangeRequired = errors.New("the password must be changed")
)

// UserState is the state of an account, managed by the administrators. It is
// kept by subject, so it works with the users of any store (SQLite, LDAP or
// the configuration file).
type UserState struct {
	Subject string

	// Disabled accounts cannot sign in until an administrator enables them
	Disabled       bool
	DisabledReason string
	DisabledAt     time.Time
	DisabledBy     string

	// Locked accounts cannot sign in until LockedUntil (zero: until an
	// administrator unlocks them)
	Locked      bool
	LockedUntil time.Time
	LockReason  string
	LockedAt    time.Time
	LockedBy    string

	// PasswordChangeRequired is set with the temporary passwords
	PasswordChangeRequired bool
}

// IsLocked is true while the lock lasts
func (s UserState) IsLocked(now time.Time) bool {
	return s.Locked && (s.LockedUntil.IsZero() || now.Before(s.LockedUntil))
}

// CanSignIn returns ErrAccountDisabled or ErrAccountLocked if the user cannot sign in
func (s UserState) CanSignIn(now time.Time) error {
	switch {
	case s.Disabled:
		return ErrAccountDisabled
	case s.IsLocked(now):
		return ErrAccountLocked
	default:
		return nil
	}
}

type UserStateStore interface {
	// GetUserState returns the state of the user (an empty state if it has none)
	GetUserState(subject string) (UserState, error)
	SaveUserState(state UserState) error
	DeleteUserState(subject string) error
}

// CheckSignIn returns an error if the user cannot sign in: the account is
// disabled or locked, or the state cannot be read (it fails closed)
func CheckSignIn(store UserStateStore, subject string, now time.Time) error {
	state, err := store.GetUserState(subject)
	if err != nil {
		return err
	}

	return state.CanSignIn(now)
}

// PasswordResetStore keeps the password reset links: single use links that
// the administrators give to the users (there is no email)
type PasswordResetStore interface {
	// NewPasswordReset stores the hash of a reset token. The previous tokens
	// of the user stop working.
	NewPasswordReset(tokenHash, userID string, expiresAt time.Time) error
	// CheckPasswordReset returns the user of a valid token
	CheckPasswordReset(tokenHash string, now time.Time) (string, error)
	// TakePasswordReset returns the user of a valid token and deletes it
	TakePasswordReset(tokenHash string, now time.Time) (string, error)
	DeleteUserPasswordResets(userID string) error
	CleanExpired(now time.Time)
}

package domain

import "time"

// UserBlockedStore counts failed attempts (login, MFA...) per key and blocks
// the key temporarily when there are too many, to prevent brute force attacks.
type UserBlockedStore interface {
	// AddFailedAttempt registers a failed attempt and returns true if the key is now blocked
	AddFailedAttempt(key string, now time.Time) bool
	// IsBlocked returns true if the key is blocked
	IsBlocked(key string, now time.Time) bool
	// Reset forgets the failed attempts of the key
	Reset(key string)
	CleanExpired(now time.Time)
}

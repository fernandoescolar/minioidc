package domain

import "time"

// ClientAssertionStore remembers the used client assertions (the jti of
// client_secret_jwt and private_key_jwt) until they expire, so they cannot be
// replayed (RFC 7523 section 3). Share it between instances to detect replays
// sent to different instances.
type ClientAssertionStore interface {
	// Use registers the assertion ID. It returns false if it has already been
	// used and it has not expired yet.
	Use(id string, expiresAt, now time.Time) (bool, error)
	CleanExpired(now time.Time)
}

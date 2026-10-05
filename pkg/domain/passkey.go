package domain

import "time"

// Passkey is a WebAuthn credential of a user
type Passkey struct {
	// ID is the credential ID (base64url)
	ID     string
	UserID string
	// Name is the name given by the user (e.g. "MacBook")
	Name string
	// Credential is the WebAuthn credential (public key, sign count, flags…)
	// encoded as JSON: the stores keep it as it is
	Credential []byte
	CreatedAt  time.Time
	// LastUsedAt is zero if the passkey has not been used to sign in
	LastUsedAt time.Time
}

type PasskeyStore interface {
	AddPasskey(passkey Passkey) error
	GetPasskey(id string) (Passkey, error)
	// ListPasskeys returns the passkeys of a user, the oldest first
	ListPasskeys(userID string) ([]Passkey, error)
	// UsePasskey stores the credential after a login (its sign count changes)
	UsePasskey(id string, credential []byte, usedAt time.Time) error
	// RenamePasskey and DeletePasskey fail if the passkey is not of the user
	RenamePasskey(userID, id, name string) error
	DeletePasskey(userID, id string) error
	DeleteUserPasskeys(userID string) error
}

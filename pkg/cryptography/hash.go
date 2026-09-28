package cryptography

import (
	"crypto/sha256"
	"encoding/base64"
)

// SHA256 returns the base64url encoded SHA-256 hash of a text
func SHA256(text string) string {
	sum := sha256.Sum256([]byte(text))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

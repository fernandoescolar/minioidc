package cryptography

import (
	"crypto/sha256"
	"encoding/base64"
)

func SHA256(text string) string {
	return base64.RawURLEncoding.EncodeToString(SHA256b([]byte(text)))
}

func SHA256b(bytes []byte) []byte {
	hasher := sha256.New()
	return hasher.Sum(bytes)
}

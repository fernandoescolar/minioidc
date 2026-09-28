package cryptography

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const (
	DefaultCypherCost = 12
	tokenLength       = 32
)

// HashPassword hashes a password with the default cypher cost
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), DefaultCypherCost)
	return string(bytes), err
}

// CheckPasswordHash compares a password with a hash and returns true if they match
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// RandomPassword generates a random base32 password from the specified number of random bytes
func RandomPassword(length int) (string, error) {
	secret := make([]byte, length)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("error reading random: %w", err)
	}

	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// RandomToken generates an opaque random token (256 bits) base64url encoded
func RandomToken() (string, error) {
	token := make([]byte, tokenLength)
	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("error reading random: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(token), nil
}

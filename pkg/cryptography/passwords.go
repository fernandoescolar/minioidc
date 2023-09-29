package cryptography

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const (
	DefaultCypherCost = 6 // recommended value for non admin users
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

// RandomPassword generates a random password of the specified length
func RandomPassword(length int) (string, error) {
	var result string
	secret := make([]byte, length)
	gen, err := rand.Read(secret)
	if err != nil || gen != length {
		return result, fmt.Errorf("error reading random: %w", err)
	}

	var encoder = base32.StdEncoding.WithPadding(base32.NoPadding)
	result = encoder.EncodeToString(secret)
	return result, nil
}

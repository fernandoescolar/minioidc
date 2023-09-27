package cryptography

import (
	"golang.org/x/crypto/bcrypt"
)

const (
	DefaultCypherCost = 6 // recommended value for non admin users
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), DefaultCypherCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

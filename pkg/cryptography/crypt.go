package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// MinMasterKeyLength is the minimum length allowed for the key used in Encrypts and Decrypts
const MinMasterKeyLength = 32

// Encrypts encrypts and authenticates a text using AES-256-GCM. The result is base64url encoded.
func Encrypts(key, text string) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	sealed := gcm.Seal(nonce, nonce, []byte(text), nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Decrypts decrypts a text encrypted with Encrypts. It fails if the text has been tampered.
func Decrypts(key, text string) (string, error) {
	data, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}

	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}

	if len(data) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plain), nil
}

func newGCM(key string) (cipher.AEAD, error) {
	// derive a 256 bits key from the whole master key
	derived := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(derived[:])
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

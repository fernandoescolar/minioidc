package cryptography

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func EncryptAndDecrypt(t *testing.T) {
	key := "12345678901234567890abcdefghijklmnopqrstuvwxyz"
	text := "Hello, World!"
	encrypted, err := Encrypts(key, text)
	if err != nil {
		t.Error(err)
	}
	decrypted, err := Decrypts(key, encrypted)
	if err != nil {
		t.Error(err)
	}
	if decrypted != text {
		t.Errorf("Expected %s, got %s", text, decrypted)
	}
}

func TokenEncryptAndDecrypt(t *testing.T) {
	key := "12345678901234567890123456789012"
	text := strings.ReplaceAll(uuid.New().String()+uuid.New().String(), "-", "")
	encrypted, err := Encrypts(key, text)
	if err != nil {
		t.Error(err)
	}

	fmt.Println("E: %w", encrypted)
	decrypted, err := Decrypts(key, encrypted)
	if err != nil {
		t.Error(err)
	}

	fmt.Println("D: %w", encrypted)
	if decrypted != text {
		t.Errorf("Expected %s, got %s", text, decrypted)
	}
}

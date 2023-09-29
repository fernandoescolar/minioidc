package cryptography

import "testing"

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

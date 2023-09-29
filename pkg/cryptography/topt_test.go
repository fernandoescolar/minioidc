package cryptography

import (
	"testing"
	"time"
)

func TestTOTPIsInvalid(t *testing.T) {
	passphrase := "12345678901234567890abcdefghijklmnopqrstuvwxyz"
	secretKey1 := []byte(passphrase)
	secretKey2 := []byte(passphrase)

	totp1 := NewTOTP(secretKey1, 1, 10)
	totp2 := NewTOTP(secretKey2, 1, 10)

	code := totp1.Compute()
	time.Sleep(2 * time.Second)

	verified := totp2.Verify(code, -1, 1)
	if verified {
		t.Error("Expected invalid TOTP code, but it was verified as valid.")
	}
}

func TestTOTPIsValid(t *testing.T) {
	passphrase := "12345678901234567890abcdefghijklmnopqrstuvwxyz"
	secretKey1 := []byte(passphrase)
	secretKey2 := []byte(passphrase)

	totp1 := NewTOTP(secretKey1, 1, 10)
	totp2 := NewTOTP(secretKey2, 1, 10)

	code := totp1.Compute()
	time.Sleep(1 * time.Second)

	verified := totp2.Verify(code, -1, 1)
	if !verified {
		t.Error("Expected valid TOTP code, but it was not verified as valid.")
	}
}

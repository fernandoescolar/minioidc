package cryptography

import (
	"testing"
	"time"
)

func TestTOTPIsInvalid(t *testing.T) {
	passphrase := "IJKLMNOPQRSTUVWXYZ"

	totp1 := NewTOTP(passphrase, 1, 10)
	totp2 := NewTOTP(passphrase, 1, 10)

	code := totp1.Compute()
	time.Sleep(2 * time.Second)

	verified := totp2.Verify(code, -1, 1)
	if verified {
		t.Error("Expected invalid TOTP code, but it was verified as valid.")
	}
}

func TestTOTPIsValid(t *testing.T) {
	passphrase := "IJKLMNOPQRSTUVWXYZ"

	totp1 := NewTOTP(passphrase, 1, 10)
	totp2 := NewTOTP(passphrase, 1, 10)

	code := totp1.Compute()
	time.Sleep(1 * time.Second)

	verified := totp2.Verify(code, -1, 1)
	if !verified {
		t.Error("Expected valid TOTP code, but it was not verified as valid.")
	}
}

func TestTOTPVerifyByTime(t *testing.T) {
	passphrase := "4S62BZNFXXSZLCRO"
	totp := NewTOTP(passphrase, 30, 6)
	code := totp.ComputeAt(time.Unix(1524486261, 0))
	if code != "730876" {
		t.Errorf("Expected TOTP code to be %s, but it was %s", "492039", code)
	}

	verified := totp.VerifyAt("730876", time.Unix(1524486261, 0), 0, 1)
	if !verified {
		t.Error("Expected valid TOTP code, but it was not verified as valid.")
	}

	verified = totp.VerifyAt("492039", time.Unix(1520000000, 0), 1, 2)
	if verified {
		t.Error("Expected invalid TOTP code, but it was verified as valid.")
	}
}

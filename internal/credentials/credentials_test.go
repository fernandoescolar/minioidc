package credentials

import (
	"errors"
	"testing"
	"time"

	"github.com/fernandoescolar/minioidc/internal/stores"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func newChecker(t *testing.T, requireMFA bool) (*Checker, string) {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	users := stores.NewUserStore()
	for _, u := range []domain.UserData{
		{Subject: "1", PreferredUsername: "alice", PasswordHash: string(hash)},
		{Subject: "2", PreferredUsername: "bob", PasswordHash: string(hash)},
	} {
		if _, err := users.NewUser(u); err != nil {
			t.Fatal(err)
		}
	}

	// bob has MFA
	mfa := stores.NewMFACodeStore(users)
	bob, _ := users.GetUserByID("2")
	secret, _ := cryptography.NewTOTPSecret()
	if _, err := mfa.NewMFACode("m1", bob, secret, cryptography.TOTPMethod); err != nil {
		t.Fatal(err)
	}

	return &Checker{Users: users, MFA: mfa, Blocked: stores.NewUserBlockedStore(), RequireMFA: requireMFA}, secret
}

func TestAuthenticate(t *testing.T) {
	c, secret := newChecker(t, false)
	now := time.Now()

	if user, mfa, err := c.Authenticate("alice", "password", now); err != nil || user.ID() != "1" || mfa {
		t.Fatalf("Expected alice to authenticate without MFA: %v", err)
	}

	// bob has MFA: the password alone is not enough
	if _, _, err := c.Authenticate("bob", "password", now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Expected bob to need the TOTP code: %v", err)
	}

	code, _ := totp.GenerateCode(secret, now)
	if user, mfa, err := c.Authenticate("bob", "password"+code, now); err != nil || user.ID() != "2" || !mfa {
		t.Fatalf("Expected bob to authenticate with the TOTP code: %v", err)
	}

	if _, _, err := c.Authenticate("alice", "", now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Expected an empty password to fail: %v", err)
	}
}

func TestAuthenticateRequireMFA(t *testing.T) {
	c, _ := newChecker(t, true)

	// with require_mfa, the users without MFA cannot use these logins
	if _, _, err := c.Authenticate("alice", "password", time.Now()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Expected alice to be rejected: %v", err)
	}
}

func TestAuthenticateBlocksBruteForce(t *testing.T) {
	c, _ := newChecker(t, false)
	now := time.Now()

	var err error
	for i := 0; i < stores.DefaultMaxFailedAttempts; i++ {
		_, _, err = c.Authenticate("Alice", "wrong", now)
	}
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("Expected the user to be blocked: %v", err)
	}

	// blocked, even with the right password (and the key ignores the case)
	if _, _, err := c.Authenticate("alice", "password", now); !errors.Is(err, ErrBlocked) {
		t.Fatalf("Expected the user to stay blocked: %v", err)
	}
}

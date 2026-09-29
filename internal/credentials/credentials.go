// Package credentials checks the passwords of the non interactive logins
// (LDAP binds and the password grant), where the MFA code cannot be asked in
// a second step: the users with MFA write their TOTP code at the end of the
// password (e.g. "secret123456").
package credentials

import (
	"errors"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

const totpLength = 6

var (
	// ErrBlocked means that there are too many failed attempts
	ErrBlocked = errors.New("too many failed attempts")
	// ErrInvalid means that the credentials are not valid
	ErrInvalid = errors.New("invalid credentials")
)

// Checker checks the credentials with the brute force protection of the login page
type Checker struct {
	Users      domain.UserStore
	MFA        domain.MFACodeStore
	Blocked    domain.UserBlockedStore
	RequireMFA bool
}

// Authenticate returns the user and whether the MFA code was verified
func (c *Checker) Authenticate(username, password string, now time.Time) (domain.User, bool, error) {
	key := LoginBlockKey(username)
	if c.Blocked.IsBlocked(key, now) {
		return nil, false, ErrBlocked
	}

	user, mfa, ok := c.check(username, password, now)
	if !ok {
		if c.Blocked.AddFailedAttempt(key, now) {
			return nil, false, ErrBlocked
		}
		return nil, false, ErrInvalid
	}

	c.Blocked.Reset(key)
	return user, mfa, nil
}

func (c *Checker) check(username, password string, now time.Time) (domain.User, bool, bool) {
	if username == "" || password == "" {
		return nil, false, false
	}

	// the password alone: only valid when the user does not need MFA
	if user, err := c.Users.GetUserByUsernameAndPassword(username, password); err == nil {
		hasMFA, err := c.MFA.UserHasMFACodes(user.ID())
		return user, false, err == nil && !hasMFA && !c.RequireMFA
	}

	// the password followed by the TOTP code
	if len(password) <= totpLength {
		return nil, false, false
	}

	code := password[len(password)-totpLength:]
	user, err := c.Users.GetUserByUsernameAndPassword(username, password[:len(password)-totpLength])
	if err != nil {
		return nil, false, false
	}

	codes, err := c.MFA.GetMFACodeByUserID(user.ID())
	if err != nil {
		return nil, false, false
	}

	for _, mfa := range codes {
		if cryptography.VerifyTOTP(mfa.Method(), mfa.Secret(), code, now) {
			return user, true, true
		}
	}

	return nil, false, false
}

// LoginBlockKey is the key of the failed login attempts of a user, shared by
// the login page, the LDAP server and the password grant
func LoginBlockKey(username string) string {
	return "login:" + strings.ToLower(username)
}

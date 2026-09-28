package domain

import (
	"encoding/json"
	"strings"

	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/golang-jwt/jwt/v5"
)

type UserStore interface {
	NewUser(data UserData) (User, error)
	GetUserByID(id string) (User, error)
	GetUserByUsernameAndPassword(username string, password string) (User, error)
}

// UserLister is implemented by the user stores that can list their users
// (SQLite and the users of the configuration, not LDAP)
type UserLister interface {
	ListUsers() ([]UserData, error)
}

// UserAdminStore is implemented by the user stores that can be managed from the admin web
type UserAdminStore interface {
	UserStore
	UserLister
	// UpdateUser replaces the user. An empty PasswordHash keeps the current password.
	UpdateUser(data UserData) error
	DeleteUser(id string) error
}

type User interface {
	ID() string
	// Data returns the properties of the user (including the password hash)
	Data() UserData
	// InGroup returns true if the user is member of the group. LDAP groups can
	// be compared by DN or by the value of their first RDN (e.g. the cn).
	InGroup(group string) bool
	Username() string
	Userinfo([]string) ([]byte, error)
	Claims([]string, *IDTokenClaims) (jwt.Claims, error)
	PasswordIsValid(string) bool
}

// UserData are the properties of a user
type UserData struct {
	Subject           string
	Email             string
	EmailVerified     bool
	PreferredUsername string
	Name              string
	GivenName         string
	FamilyName        string
	Phone             string
	Address           string
	Groups            []string
	PasswordHash      string
}

// user is a default implementation of the User interface
type user struct {
	UserData
}

// standardClaims are the user claims of the userinfo endpoint and the ID token
type standardClaims struct {
	Email             string        `json:"email,omitempty"`
	EmailVerified     *bool         `json:"email_verified,omitempty"`
	PreferredUsername string        `json:"preferred_username,omitempty"`
	Name              string        `json:"name,omitempty"`
	GivenName         string        `json:"given_name,omitempty"`
	FamilyName        string        `json:"family_name,omitempty"`
	Phone             string        `json:"phone_number,omitempty"`
	Address           *addressClaim `json:"address,omitempty"`
	Groups            []string      `json:"groups,omitempty"`
}

type miniUserinfo struct {
	Subject string `json:"sub"`
	standardClaims
}

// addressClaim is the OIDC address claim (OIDC Core section 5.1.1). The
// address is kept as a single text, so only the formatted member is used.
type addressClaim struct {
	Formatted string `json:"formatted"`
}

type miniClaims struct {
	*IDTokenClaims
	standardClaims
}

// NewUser creates a new User
func NewUser(data UserData) User {
	return &user{UserData: data}
}

func (u *user) ID() string {
	return u.Subject
}

func (u *user) Data() UserData {
	data := u.UserData
	data.Groups = append([]string{}, u.Groups...)
	return data
}

func (u *user) InGroup(group string) bool {
	if group == "" {
		return false
	}

	for _, g := range u.Groups {
		if strings.EqualFold(g, group) || strings.EqualFold(firstRDNValue(g), group) {
			return true
		}
	}

	return false
}

// firstRDNValue returns "admins" for "cn=admins,ou=groups,dc=example,dc=com"
func firstRDNValue(dn string) string {
	rdn, _, _ := strings.Cut(dn, ",")
	_, value, found := strings.Cut(rdn, "=")
	if !found {
		return ""
	}

	return strings.TrimSpace(value)
}

func (u *user) Username() string {
	if u.Email != "" {
		return u.Email
	}

	return u.PreferredUsername
}

func (u *user) Userinfo(scopes []string) ([]byte, error) {
	return json.Marshal(&miniUserinfo{
		Subject:        u.Subject,
		standardClaims: u.scopedClaims(scopes),
	})
}

func (u *user) Claims(scopes []string, claims *IDTokenClaims) (jwt.Claims, error) {
	return &miniClaims{
		IDTokenClaims:  claims,
		standardClaims: u.scopedClaims(scopes),
	}, nil
}

func (u *user) PasswordIsValid(password string) bool {
	return cryptography.CheckPasswordHash(password, u.PasswordHash)
}

// scopedClaims returns the standard claims of each scope: OIDC Core section 5.4
func (u *user) scopedClaims(scopes []string) standardClaims {
	claims := standardClaims{}
	for _, scope := range scopes {
		switch scope {
		case "profile":
			claims.PreferredUsername = u.PreferredUsername
			claims.Name = u.Name
			claims.GivenName = u.GivenName
			claims.FamilyName = u.FamilyName
		case "email":
			if u.Email != "" {
				verified := u.EmailVerified
				claims.Email = u.Email
				claims.EmailVerified = &verified
			}
		case "address":
			if u.Address != "" {
				claims.Address = &addressClaim{Formatted: u.Address}
			}
		case "phone":
			claims.Phone = u.Phone
		case "groups":
			claims.Groups = append(make([]string, 0, len(u.Groups)), u.Groups...)
		}
	}

	return claims
}

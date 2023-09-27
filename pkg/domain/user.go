package domain

import (
	"encoding/json"

	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/golang-jwt/jwt"
)

type UserStore interface {
	NewUser(subject, email, preferredUsername, phone, address string, groups []string, passwordHash string) (User, error)
	GetUserByID(id string) (User, error)
	GetUserByToken(token string) (User, error)
	GetUserByUsername(email string) (User, error)
	DeleteUser(id string)
}

type User interface {
	ID() string
	Username() string
	Userinfo([]string) ([]byte, error)
	Claims([]string, *IDTokenClaims) (jwt.Claims, error)
	PasswordIsValid(string) bool
}

// user is a default implementation of the User interface
type user struct {
	Subject           string
	Email             string
	EmailVerified     bool
	PreferredUsername string
	Phone             string
	Address           string
	Groups            []string
	PasswordHash      string
}

type miniUserinfo struct {
	Email             string   `json:"email,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Phone             string   `json:"phone_number,omitempty"`
	Address           string   `json:"address,omitempty"`
	Groups            []string `json:"groups,omitempty"`
}

// NewUser creates a new User
func NewUser(subject, email, preferredUsername, phone, address string, groups []string, passwordHash string) (User, error) {
	return &user{
		Subject:           subject,
		Email:             email,
		PreferredUsername: preferredUsername,
		Phone:             phone,
		Address:           address,
		Groups:            groups,
		PasswordHash:      passwordHash,
	}, nil
}

func (u *user) ID() string {
	return u.Subject
}

func (u *user) Username() string {
	return u.Email
}

func (u *user) Userinfo(scope []string) ([]byte, error) {
	user := u.scopedClone(scope)

	info := &miniUserinfo{
		Email:             user.Email,
		PreferredUsername: user.PreferredUsername,
		Phone:             user.Phone,
		Address:           user.Address,
		Groups:            user.Groups,
	}

	return json.Marshal(info)
}

type miniClaims struct {
	*IDTokenClaims
	Email             string   `json:"email,omitempty"`
	EmailVerified     bool     `json:"email_verified,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Phone             string   `json:"phone_number,omitempty"`
	Address           string   `json:"address,omitempty"`
	Groups            []string `json:"groups,omitempty"`
}

func (u *user) Claims(scope []string, claims *IDTokenClaims) (jwt.Claims, error) {
	user := u.scopedClone(scope)

	return &miniClaims{
		IDTokenClaims:     claims,
		Email:             user.Email,
		EmailVerified:     true,
		PreferredUsername: user.PreferredUsername,
		Phone:             user.Phone,
		Address:           user.Address,
		Groups:            user.Groups,
	}, nil
}

func (u *user) PasswordIsValid(password string) bool {
	return cryptography.CheckPasswordHash(password, u.PasswordHash)
}

func (u *user) scopedClone(scopes []string) *user {
	clone := &user{
		Subject: u.Subject,
	}

	for _, scope := range scopes {
		switch scope {
		case "profile":
			clone.PreferredUsername = u.PreferredUsername
			clone.Address = u.Address
			clone.Phone = u.Phone
		case "email":
			clone.Email = u.Email
			clone.EmailVerified = true
		case "groups":
			clone.Groups = append(make([]string, 0, len(u.Groups)), u.Groups...)
		}
	}

	return clone
}

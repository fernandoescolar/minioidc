package stores

import (
	"errors"
	"fmt"
	"sync"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type miniUser struct {
	subject           string
	email             string
	preferredUsername string
	phone             string
	address           string
	groups            []string
	passwordHash      string
}

type miniUserStore struct {
	sync.Map
}

// NewUserStore initializes the UserStore for this server
func NewUserStore() domain.UserStore {
	return &miniUserStore{}
}

// NewUser creates a new User
func (us *miniUserStore) NewUser(subject, email, preferredUsername, phone, address string, groups []string, passwordHash string) (domain.User, error) {
	user := &miniUser{
		subject:           subject,
		email:             email,
		preferredUsername: preferredUsername,
		phone:             phone,
		address:           address,
		groups:            groups,
		passwordHash:      passwordHash,
	}

	us.Store(user.subject, user)
	return user.User(), nil
}

// GetUserByID looks up the User
func (us *miniUserStore) GetUserByID(id string) (domain.User, error) {
	v, ok := us.Load(id)
	if !ok {
		return nil, errors.New("user not found")
	}

	user := v.(*miniUser)
	return user.User(), nil
}

// GetUserByUsername looks up a User by their username
func (us *miniUserStore) GetUserByUsername(username string) (domain.User, error) {
	var user *miniUser
	us.Range(func(k, v interface{}) bool {
		u := v.(*miniUser)
		if u.preferredUsername == username {
			user = u
			return false
		}

		return true
	})

	if user != nil {
		return user.User(), nil
	}

	return nil, errors.New("user not found")
}

// GetUserByUsernameAndPassword looks up a User by their username and password
func (us *miniUserStore) GetUserByUsernameAndPassword(username string, password string) (domain.User, error) {
	user, err := us.GetUserByUsername(username)
	if err != nil {
		return nil, fmt.Errorf("GetUserByUsernameAndPassword: %w", err)
	}

	if user.PasswordIsValid(password) {
		return user, nil
	}

	return nil, errors.New("user not found")
}

// DeleteUser deletes a User from the cache
func (us *miniUserStore) DeleteUser(id string) {
	us.Delete(id)
}

func (u *miniUser) User() domain.User {
	return domain.NewUser(u.subject, u.email, u.preferredUsername, u.phone, u.address, u.groups, u.passwordHash)
}

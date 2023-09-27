package stores

import (
	"errors"
	"fmt"
	"sync"

	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/golang-jwt/jwt"
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
	sync.RWMutex
	store map[string]*miniUser
}

// NewUserStore initializes the UserStore for this server
func NewUserStore() domain.UserStore {
	return &miniUserStore{
		store: make(map[string]*miniUser),
	}
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

	us.Lock()
	defer us.Unlock()

	us.store[user.subject] = user

	return user.User()
}

// GetUserByID looks up the User
func (us *miniUserStore) GetUserByID(id string) (domain.User, error) {
	us.RLock()
	defer us.RUnlock()

	user, ok := us.store[id]
	if !ok {
		return nil, errors.New("user not found")
	}
	return user.User()
}

// GetUserByToken decodes a token and looks up a User based on the
// user ID claim.
func (us *miniUserStore) GetUserByToken(token string) (domain.User, error) {
	claims := &domain.IDTokenClaims{}
	_, err := jwt.ParseWithClaims(token, claims, nil)
	if err != nil {
		return nil, fmt.Errorf("GetUserByToken: %w", err)
	}

	return us.GetUserByID(claims.Subject)
}

// GetUserByUsername looks up a User by their username
func (us *miniUserStore) GetUserByUsername(username string) (domain.User, error) {
	us.RLock()
	defer us.RUnlock()

	for _, user := range us.store {
		user := *user
		if user.preferredUsername == username {
			return user.User()
		}
	}

	return nil, errors.New("user not found")
}

// DeleteUser deletes a User from the cache
func (us *miniUserStore) DeleteUser(id string) {
	us.Lock()
	defer us.Unlock()

	delete(us.store, id)
}

func (u *miniUser) User() (domain.User, error) {
	user, err := domain.NewUser(u.subject, u.email, u.preferredUsername, u.phone, u.address, u.groups, u.passwordHash)
	if err != nil {
		return nil, fmt.Errorf("toUser: %w", err)
	}

	return user, nil
}

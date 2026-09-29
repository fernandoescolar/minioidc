package stores

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// dummyPasswordHash is compared when the user does not exist, so the response
// time does not reveal which users exist
var dummyPasswordHash, _ = cryptography.HashPassword("minioidc-dummy-password")

type miniUserStore struct {
	sync.Map
}

// NewUserStore initializes the UserStore for this server
func NewUserStore() domain.UserStore {
	return &miniUserStore{}
}

// NewUser creates a new User
func (us *miniUserStore) NewUser(data domain.UserData) (domain.User, error) {
	if data.Subject == "" {
		return nil, errors.New("user subject is required")
	}

	us.Store(data.Subject, data)
	return domain.NewUser(data), nil
}

// GetUserByID looks up the User
func (us *miniUserStore) GetUserByID(id string) (domain.User, error) {
	v, ok := us.Load(id)
	if !ok {
		return nil, errors.New("user not found")
	}

	return domain.NewUser(v.(domain.UserData)), nil
}

// GetUserByUsername looks up a User by their username
func (us *miniUserStore) GetUserByUsername(username string) (domain.User, error) {
	var user *domain.UserData
	us.Range(func(_, v interface{}) bool {
		u := v.(domain.UserData)
		if u.PreferredUsername == username {
			user = &u
			return false
		}

		return true
	})

	if user == nil {
		return nil, errors.New("user not found")
	}

	return domain.NewUser(*user), nil
}

// GetUserByUsernameAndPassword looks up a User by their username and password
func (us *miniUserStore) GetUserByUsernameAndPassword(username string, password string) (domain.User, error) {
	user, err := us.GetUserByUsername(username)
	if err != nil {
		cryptography.CheckPasswordHash(password, dummyPasswordHash)
		return nil, fmt.Errorf("GetUserByUsernameAndPassword: %w", err)
	}

	if user.PasswordIsValid(password) {
		return user, nil
	}

	return nil, errors.New("user not found")
}

// UpdatePassword changes the password of a User (until the next restart: the
// users of the configuration file are not persisted)
func (us *miniUserStore) UpdatePassword(userID, passwordHash string) error {
	v, ok := us.Load(userID)
	if !ok {
		return errors.New("user not found")
	}

	data := v.(domain.UserData)
	data.PasswordHash = passwordHash
	us.Store(userID, data)
	return nil
}

// ListUsers returns all the Users sorted by username
func (us *miniUserStore) ListUsers() ([]domain.UserData, error) {
	users := []domain.UserData{}
	us.Range(func(_, v interface{}) bool {
		users = append(users, v.(domain.UserData))
		return true
	})

	sort.Slice(users, func(i, j int) bool { return users[i].PreferredUsername < users[j].PreferredUsername })
	return users, nil
}

// DeleteUser deletes a User from the cache
func (us *miniUserStore) DeleteUser(id string) {
	us.Delete(id)
}

package stores

import (
	"errors"
	"sync"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

var errPasswordResetNotFound = errors.New("the password reset link is not valid or has expired")

type miniUserStateStore struct {
	mu     sync.RWMutex
	states map[string]domain.UserState
}

// NewUserStateStore initializes a UserStateStore in memory
func NewUserStateStore() domain.UserStateStore {
	return &miniUserStateStore{states: map[string]domain.UserState{}}
}

func (s *miniUserStateStore) GetUserState(subject string) (domain.UserState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if state, ok := s.states[subject]; ok {
		return state, nil
	}

	return domain.UserState{Subject: subject}, nil
}

func (s *miniUserStateStore) SaveUserState(state domain.UserState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state.Subject] = state
	return nil
}

func (s *miniUserStateStore) DeleteUserState(subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.states, subject)
	return nil
}

type miniPasswordReset struct {
	userID    string
	expiresAt time.Time
}

type miniPasswordResetStore struct {
	mu     sync.Mutex
	resets map[string]miniPasswordReset
}

// NewPasswordResetStore initializes a PasswordResetStore in memory
func NewPasswordResetStore() domain.PasswordResetStore {
	return &miniPasswordResetStore{resets: map[string]miniPasswordReset{}}
}

func (s *miniPasswordResetStore) NewPasswordReset(tokenHash, userID string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, reset := range s.resets {
		if reset.userID == userID {
			delete(s.resets, hash)
		}
	}

	s.resets[tokenHash] = miniPasswordReset{userID: userID, expiresAt: expiresAt}
	return nil
}

func (s *miniPasswordResetStore) CheckPasswordReset(tokenHash string, now time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reset, ok := s.resets[tokenHash]
	if !ok || !now.Before(reset.expiresAt) {
		return "", errPasswordResetNotFound
	}

	return reset.userID, nil
}

func (s *miniPasswordResetStore) TakePasswordReset(tokenHash string, now time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reset, ok := s.resets[tokenHash]
	if !ok {
		return "", errPasswordResetNotFound
	}

	delete(s.resets, tokenHash)
	if !now.Before(reset.expiresAt) {
		return "", errPasswordResetNotFound
	}

	return reset.userID, nil
}

func (s *miniPasswordResetStore) DeleteUserPasswordResets(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, reset := range s.resets {
		if reset.userID == userID {
			delete(s.resets, hash)
		}
	}

	return nil
}

func (s *miniPasswordResetStore) CleanExpired(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, reset := range s.resets {
		if !now.Before(reset.expiresAt) {
			delete(s.resets, hash)
		}
	}
}

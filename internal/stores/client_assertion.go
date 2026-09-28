package stores

import (
	"sync"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type miniClientAssertionStore struct {
	mu   sync.Mutex
	used map[string]time.Time
}

// NewClientAssertionStore initializes an in memory ClientAssertionStore
func NewClientAssertionStore() domain.ClientAssertionStore {
	return &miniClientAssertionStore{used: map[string]time.Time{}}
}

func (s *miniClientAssertionStore) Use(id string, expiresAt, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if exp, ok := s.used[id]; ok && now.Before(exp) {
		return false, nil
	}

	s.used[id] = expiresAt
	return true, nil
}

func (s *miniClientAssertionStore) CleanExpired(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, exp := range s.used {
		if !now.Before(exp) {
			delete(s.used, id)
		}
	}
}

package stores

import (
	"sync"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

const (
	DefaultMaxFailedAttempts = 5
	DefaultFailedWindow      = 15 * time.Minute
	DefaultBlockDuration     = 15 * time.Minute
)

type userBlockedStore struct {
	mu            sync.Mutex
	entries       map[string]*failedAttempts
	maxAttempts   int
	window        time.Duration
	blockDuration time.Duration
}

type failedAttempts struct {
	count        int
	firstFailure time.Time
	blockedUntil time.Time
}

// NewUserBlockedStore blocks a key for 15 minutes after 5 failed attempts in 15 minutes
func NewUserBlockedStore() domain.UserBlockedStore {
	return NewUserBlockedStoreWithPolicy(DefaultMaxFailedAttempts, DefaultFailedWindow, DefaultBlockDuration)
}

// NewUserBlockedStoreWithPolicy blocks a key for blockDuration after maxAttempts failed attempts in window
func NewUserBlockedStoreWithPolicy(maxAttempts int, window, blockDuration time.Duration) domain.UserBlockedStore {
	return &userBlockedStore{
		entries:       make(map[string]*failedAttempts),
		maxAttempts:   maxAttempts,
		window:        window,
		blockDuration: blockDuration,
	}
}

func (s *userBlockedStore) AddFailedAttempt(key string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[key]
	if !ok || now.Sub(entry.firstFailure) > s.window {
		entry = &failedAttempts{firstFailure: now}
		s.entries[key] = entry
	}

	entry.count++
	if entry.count >= s.maxAttempts {
		entry.blockedUntil = now.Add(s.blockDuration)
		// start counting again after the block
		entry.count = 0
		entry.firstFailure = entry.blockedUntil
	}

	return now.Before(entry.blockedUntil)
}

func (s *userBlockedStore) IsBlocked(key string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[key]
	return ok && now.Before(entry.blockedUntil)
}

func (s *userBlockedStore) Reset(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.entries, key)
}

func (s *userBlockedStore) CleanExpired(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, entry := range s.entries {
		if now.After(entry.blockedUntil) && now.Sub(entry.firstFailure) > s.window {
			delete(s.entries, key)
		}
	}
}

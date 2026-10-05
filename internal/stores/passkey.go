package stores

import (
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

var errPasskeyNotFound = errors.New("passkey not found")

type miniPasskeyStore struct {
	mu       sync.RWMutex
	passkeys map[string]domain.Passkey
}

// NewPasskeyStore initializes a PasskeyStore in memory
func NewPasskeyStore() domain.PasskeyStore {
	return &miniPasskeyStore{passkeys: map[string]domain.Passkey{}}
}

func (ps *miniPasskeyStore) AddPasskey(passkey domain.Passkey) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if _, exists := ps.passkeys[passkey.ID]; exists {
		return errors.New("the passkey already exists")
	}

	ps.passkeys[passkey.ID] = copyPasskey(passkey)
	return nil
}

func (ps *miniPasskeyStore) GetPasskey(id string) (domain.Passkey, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	passkey, ok := ps.passkeys[id]
	if !ok {
		return domain.Passkey{}, errPasskeyNotFound
	}

	return copyPasskey(passkey), nil
}

func (ps *miniPasskeyStore) ListPasskeys(userID string) ([]domain.Passkey, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	passkeys := []domain.Passkey{}
	for _, passkey := range ps.passkeys {
		if passkey.UserID == userID {
			passkeys = append(passkeys, copyPasskey(passkey))
		}
	}

	sort.Slice(passkeys, func(i, j int) bool { return passkeys[i].CreatedAt.Before(passkeys[j].CreatedAt) })
	return passkeys, nil
}

func (ps *miniPasskeyStore) UsePasskey(id string, credential []byte, usedAt time.Time) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	passkey, ok := ps.passkeys[id]
	if !ok {
		return errPasskeyNotFound
	}

	passkey.Credential = append([]byte{}, credential...)
	passkey.LastUsedAt = usedAt
	ps.passkeys[id] = passkey
	return nil
}

func (ps *miniPasskeyStore) RenamePasskey(userID, id, name string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	passkey, ok := ps.passkeys[id]
	if !ok || passkey.UserID != userID {
		return errPasskeyNotFound
	}

	passkey.Name = name
	ps.passkeys[id] = passkey
	return nil
}

func (ps *miniPasskeyStore) DeletePasskey(userID, id string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	passkey, ok := ps.passkeys[id]
	if !ok || passkey.UserID != userID {
		return errPasskeyNotFound
	}

	delete(ps.passkeys, id)
	return nil
}

func (ps *miniPasskeyStore) DeleteUserPasskeys(userID string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for id, passkey := range ps.passkeys {
		if passkey.UserID == userID {
			delete(ps.passkeys, id)
		}
	}

	return nil
}

func copyPasskey(passkey domain.Passkey) domain.Passkey {
	passkey.Credential = append([]byte{}, passkey.Credential...)
	return passkey
}

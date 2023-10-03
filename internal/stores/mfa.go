package stores

import (
	"sync"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// MFACodeStore manages our MFACode objects
type miniMFACodeStore struct {
	sync.Map
	userStore domain.UserStore
}

type miniMFACode struct {
	id     string
	userID string
	secret string
	method string
}

// NewMFACodeStore initializes the MFACodeStore for this server
func NewMFACodeStore(userStore domain.UserStore) domain.MFACodeStore {
	return &miniMFACodeStore{
		userStore: userStore,
	}
}

// NewMFACode creates a new MFACode for a User
func (ms *miniMFACodeStore) NewMFACode(id string, user domain.User, secret, method string) (domain.MFACode, error) {
	mfaCode := &miniMFACode{
		id:     id,
		userID: user.ID(),
		secret: secret,
		method: method,
	}

	ms.Store(mfaCode.id, mfaCode)
	return ms.MFACode(mfaCode)
}

// UserHasMFACodes checks if a User has any MFACodes
func (ms *miniMFACodeStore) UserHasMFACodes(userID string) (bool, error) {
	var hasMFACodes bool
	ms.Range(func(key, value interface{}) bool {
		mfaCode := value.(*miniMFACode)
		if mfaCode.userID == userID {
			hasMFACodes = true
			return false
		}
		return true
	})

	return hasMFACodes, nil
}

// GetMFACodeByUserID looks up MFACodes by UserID
func (ms *miniMFACodeStore) GetMFACodeByUserID(userID string) ([]domain.MFACode, error) {
	var mfaCodes []domain.MFACode
	var err error
	ms.Range(func(key, value interface{}) bool {
		mfaCode := value.(*miniMFACode)
		if mfaCode.userID == userID {
			mfa, e := ms.MFACode(mfaCode)
			if e != nil {
				err = e
				return false
			}

			mfaCodes = append(mfaCodes, mfa)
		}
		return true
	})

	if err != nil {
		return nil, err
	}

	return mfaCodes, nil
}

// DeleteUserMFACodes deletes all MFACodes for a User
func (ms *miniMFACodeStore) DeleteUserMFACodes(userID string) {
	ms.Range(func(key, value interface{}) bool {
		mfaCode := value.(*miniMFACode)
		if mfaCode.userID == userID {
			ms.Delete(mfaCode.id)
		}
		return true
	})
}

// MFACode converts a miniMFACode to a MFACode
func (ms *miniMFACodeStore) MFACode(mfaCode *miniMFACode) (domain.MFACode, error) {
	user, err := ms.userStore.GetUserByID(mfaCode.userID)
	if err != nil {
		return nil, err
	}

	return domain.NewMFACode(mfaCode.id, user, mfaCode.secret, mfaCode.method), nil
}

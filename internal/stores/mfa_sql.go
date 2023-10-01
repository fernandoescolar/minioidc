package stores

import (
	"database/sql"

	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/google/uuid"
)

// MFACodeStore manages our MFACode objects
type sqlMFACodeStore struct {
	db        *sql.DB
	userStore domain.UserStore
}

// NewSqliteMFACodeStore initializes the MFACodeStore for this server
func NewSqliteMFACodeStore(db *sql.DB, userStore domain.UserStore) domain.MFACodeStore {
	return &sqlMFACodeStore{
		db:        db,
		userStore: userStore,
	}
}

// NewMFACode creates a new MFACode for a User
func (ms *sqlMFACodeStore) NewMFACode(user domain.User, secret, method string) (domain.MFACode, error) {
	mfaCode := &miniMFACode{
		id:     uuid.New().String(),
		userID: user.ID(),
		secret: secret,
		method: method,
	}

	_, err := ms.db.Exec("INSERT INTO mfa VALUES(?,?,?,?);", mfaCode.id, mfaCode.userID, mfaCode.secret, mfaCode.method)
	if err != nil {
		return nil, err
	}

	return ms.MFACode(mfaCode)
}

// UserHasMFACodes checks if a User has any MFACodes
func (ms *sqlMFACodeStore) UserHasMFACodes(userID string) (bool, error) {
	var hasMFACodes bool
	rows, err := ms.db.Query("SELECT id, userID, secret, method FROM mfa WHERE userID = ?;", userID)
	if err != nil {
		return false, err
	}

	defer rows.Close()
	for rows.Next() {
		hasMFACodes = true
		break
	}

	return hasMFACodes, nil
}

// GetMFACodeByUserID looks up MFACodes by UserID
func (ms *sqlMFACodeStore) GetMFACodeByUserID(userID string) ([]domain.MFACode, error) {
	var mfaCodes []domain.MFACode
	rows, err := ms.db.Query("SELECT id, userID, secret, method FROM mfa WHERE userID = ?;", userID)
	if err != nil {
		return nil, err
	}

	defer rows.Close()
	for rows.Next() {
		mfaCode := &miniMFACode{}
		err = rows.Scan(&mfaCode.id, &mfaCode.userID, &mfaCode.secret, &mfaCode.method)
		if err != nil {
			return nil, err
		}

		mfa, err := ms.MFACode(mfaCode)
		if err != nil {
			return nil, err
		}

		mfaCodes = append(mfaCodes, mfa)
	}

	return mfaCodes, nil
}

// DeleteUserMFACodes deletes all MFACodes for a User
func (ms *sqlMFACodeStore) DeleteUserMFACodes(userID string) {
	ms.db.Exec("DELETE FROM mfa WHERE userID = ?;", userID)
}

// MFACode converts a miniMFACode to a MFACode
func (ms *sqlMFACodeStore) MFACode(mfaCode *miniMFACode) (domain.MFACode, error) {
	user, err := ms.userStore.GetUserByID(mfaCode.userID)
	if err != nil {
		return nil, err
	}

	return domain.NewMFACode(mfaCode.id, user, mfaCode.secret, mfaCode.method), nil
}

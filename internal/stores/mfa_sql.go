package stores

import (
	"database/sql"
	"log"

	"github.com/fernandoescolar/minioidc/pkg/domain"
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
func (ms *sqlMFACodeStore) NewMFACode(id string, user domain.User, secret, method string) (domain.MFACode, error) {
	mfaCode := &miniMFACode{
		id:     id,
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
	var count int
	if err := ms.db.QueryRow("SELECT COUNT(*) FROM mfa WHERE userID = ?;", userID).Scan(&count); err != nil {
		return false, err
	}

	return count > 0, nil
}

// GetMFACodeByUserID looks up MFACodes by UserID
func (ms *sqlMFACodeStore) GetMFACodeByUserID(userID string) ([]domain.MFACode, error) {
	var mfaCodes []domain.MFACode
	rows, err := ms.db.Query("SELECT id, userID, secret, method FROM mfa WHERE userID = ?;", userID)
	if err != nil {
		return nil, err
	}

	// all the rows are read before looking up the user: the SQLite connection
	// is busy while the rows are open, and the users can be in SQLite too
	var codes []*miniMFACode
	for rows.Next() {
		mfaCode := &miniMFACode{}
		if err := rows.Scan(&mfaCode.id, &mfaCode.userID, &mfaCode.secret, &mfaCode.method); err != nil {
			rows.Close()
			return nil, err
		}

		codes = append(codes, mfaCode)
	}

	if err := rows.Close(); err != nil {
		return nil, err
	}

	for _, code := range codes {
		mfa, err := ms.MFACode(code)
		if err != nil {
			return nil, err
		}

		mfaCodes = append(mfaCodes, mfa)
	}

	return mfaCodes, nil
}

// DeleteUserMFACodes deletes all MFACodes for a User
func (ms *sqlMFACodeStore) DeleteUserMFACodes(userID string) {
	if _, err := ms.db.Exec("DELETE FROM mfa WHERE userID = ?;", userID); err != nil {
		log.Printf("WRN DeleteUserMFACodes: %v", err)
	}
}

// MFACode converts a miniMFACode to a MFACode
func (ms *sqlMFACodeStore) MFACode(mfaCode *miniMFACode) (domain.MFACode, error) {
	user, err := ms.userStore.GetUserByID(mfaCode.userID)
	if err != nil {
		return nil, err
	}

	return domain.NewMFACode(mfaCode.id, user, mfaCode.secret, mfaCode.method), nil
}

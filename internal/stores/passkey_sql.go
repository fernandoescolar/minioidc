package stores

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

const passkeyColumns = "id, userID, name, credential, createdAt, lastUsedAt"

type sqlPasskeyStore struct {
	db *sql.DB
}

// NewSqlitePasskeyStore initializes a PasskeyStore in SQLite. The dates are
// stored as unix milliseconds.
func NewSqlitePasskeyStore(db *sql.DB) domain.PasskeyStore {
	return &sqlPasskeyStore{db: db}
}

func (ps *sqlPasskeyStore) AddPasskey(passkey domain.Passkey) error {
	_, err := ps.db.Exec("INSERT INTO passkeys("+passkeyColumns+") VALUES(?,?,?,?,?,?);",
		passkey.ID, passkey.UserID, passkey.Name, string(passkey.Credential), passkey.CreatedAt.UnixMilli(), unixMilli(passkey.LastUsedAt))
	if err != nil {
		return fmt.Errorf("AddPasskey: %w", err)
	}

	return nil
}

func (ps *sqlPasskeyStore) GetPasskey(id string) (domain.Passkey, error) {
	passkey, err := scanPasskey(ps.db.QueryRow("SELECT "+passkeyColumns+" FROM passkeys WHERE id = ?;", id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Passkey{}, errPasskeyNotFound
	}

	return passkey, err
}

func (ps *sqlPasskeyStore) ListPasskeys(userID string) ([]domain.Passkey, error) {
	rows, err := ps.db.Query("SELECT "+passkeyColumns+" FROM passkeys WHERE userID = ? ORDER BY createdAt;", userID)
	if err != nil {
		return nil, fmt.Errorf("ListPasskeys: %w", err)
	}
	defer rows.Close()

	passkeys := []domain.Passkey{}
	for rows.Next() {
		passkey, err := scanPasskey(rows)
		if err != nil {
			return nil, fmt.Errorf("ListPasskeys: %w", err)
		}

		passkeys = append(passkeys, passkey)
	}

	return passkeys, rows.Err()
}

func (ps *sqlPasskeyStore) UsePasskey(id string, credential []byte, usedAt time.Time) error {
	r, err := ps.db.Exec("UPDATE passkeys SET credential = ?, lastUsedAt = ? WHERE id = ?;", string(credential), usedAt.UnixMilli(), id)
	if err != nil {
		return err
	}

	return expectOneRow(r, "passkey")
}

func (ps *sqlPasskeyStore) RenamePasskey(userID, id, name string) error {
	r, err := ps.db.Exec("UPDATE passkeys SET name = ? WHERE id = ? AND userID = ?;", name, id, userID)
	if err != nil {
		return err
	}

	return expectOneRow(r, "passkey")
}

func (ps *sqlPasskeyStore) DeletePasskey(userID, id string) error {
	r, err := ps.db.Exec("DELETE FROM passkeys WHERE id = ? AND userID = ?;", id, userID)
	if err != nil {
		return err
	}

	return expectOneRow(r, "passkey")
}

func (ps *sqlPasskeyStore) DeleteUserPasskeys(userID string) error {
	_, err := ps.db.Exec("DELETE FROM passkeys WHERE userID = ?;", userID)
	return err
}

func scanPasskey(row interface{ Scan(...any) error }) (domain.Passkey, error) {
	var (
		passkey               domain.Passkey
		credential            string
		createdAt, lastUsedAt int64
	)
	if err := row.Scan(&passkey.ID, &passkey.UserID, &passkey.Name, &credential, &createdAt, &lastUsedAt); err != nil {
		return domain.Passkey{}, err
	}

	passkey.Credential = []byte(credential)
	passkey.CreatedAt = time.UnixMilli(createdAt)
	if lastUsedAt > 0 {
		passkey.LastUsedAt = time.UnixMilli(lastUsedAt)
	}

	return passkey, nil
}

// unixMilli is 0 for the zero time
func unixMilli(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}

	return t.UnixMilli()
}

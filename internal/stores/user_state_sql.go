package stores

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

const userStateColumns = "subject, disabled, disabledReason, disabledAt, disabledBy, locked, lockedUntil, lockReason, lockedAt, lockedBy, passwordChangeRequired"

type sqlUserStateStore struct {
	db *sql.DB
}

// NewSqliteUserStateStore initializes a UserStateStore in SQLite. The dates
// are stored as unix milliseconds (0 is the zero time).
func NewSqliteUserStateStore(db *sql.DB) domain.UserStateStore {
	return &sqlUserStateStore{db: db}
}

func (s *sqlUserStateStore) GetUserState(subject string) (domain.UserState, error) {
	var (
		state                             = domain.UserState{Subject: subject}
		disabledAt, lockedUntil, lockedAt int64
	)
	err := s.db.QueryRow("SELECT "+userStateColumns+" FROM user_states WHERE subject = ?;", subject).Scan(
		&state.Subject, &state.Disabled, &state.DisabledReason, &disabledAt, &state.DisabledBy,
		&state.Locked, &lockedUntil, &state.LockReason, &lockedAt, &state.LockedBy, &state.PasswordChangeRequired)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.UserState{Subject: subject}, nil
	}
	if err != nil {
		return domain.UserState{}, fmt.Errorf("GetUserState: %w", err)
	}

	state.DisabledAt = fromUnixMilli(disabledAt)
	state.LockedUntil = fromUnixMilli(lockedUntil)
	state.LockedAt = fromUnixMilli(lockedAt)
	return state, nil
}

func (s *sqlUserStateStore) SaveUserState(state domain.UserState) error {
	_, err := s.db.Exec("INSERT OR REPLACE INTO user_states("+userStateColumns+") VALUES(?,?,?,?,?,?,?,?,?,?,?);",
		state.Subject, state.Disabled, state.DisabledReason, unixMilli(state.DisabledAt), state.DisabledBy,
		state.Locked, unixMilli(state.LockedUntil), state.LockReason, unixMilli(state.LockedAt), state.LockedBy, state.PasswordChangeRequired)
	if err != nil {
		return fmt.Errorf("SaveUserState: %w", err)
	}

	return nil
}

func (s *sqlUserStateStore) DeleteUserState(subject string) error {
	_, err := s.db.Exec("DELETE FROM user_states WHERE subject = ?;", subject)
	return err
}

type sqlPasswordResetStore struct {
	db *sql.DB
}

// NewSqlitePasswordResetStore initializes a PasswordResetStore in SQLite
func NewSqlitePasswordResetStore(db *sql.DB) domain.PasswordResetStore {
	return &sqlPasswordResetStore{db: db}
}

func (s *sqlPasswordResetStore) NewPasswordReset(tokenHash, userID string, expiresAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec("DELETE FROM password_resets WHERE userID = ?;", userID); err != nil {
		return err
	}
	if _, err := tx.Exec("INSERT INTO password_resets(id, userID, expiresAt) VALUES(?,?,?);", tokenHash, userID, expiresAt); err != nil {
		return fmt.Errorf("NewPasswordReset: %w", err)
	}

	return tx.Commit()
}

func (s *sqlPasswordResetStore) CheckPasswordReset(tokenHash string, now time.Time) (string, error) {
	var (
		userID    string
		expiresAt time.Time
	)
	err := s.db.QueryRow("SELECT userID, expiresAt FROM password_resets WHERE id = ?;", tokenHash).Scan(&userID, &expiresAt)
	if err != nil || !now.Before(expiresAt) {
		return "", errPasswordResetNotFound
	}

	return userID, nil
}

func (s *sqlPasswordResetStore) TakePasswordReset(tokenHash string, now time.Time) (string, error) {
	var (
		userID    string
		expiresAt time.Time
	)
	// the DELETE is the single use: only one request deletes the row
	err := s.db.QueryRow("DELETE FROM password_resets WHERE id = ? RETURNING userID, expiresAt;", tokenHash).Scan(&userID, &expiresAt)
	if err != nil || !now.Before(expiresAt) {
		return "", errPasswordResetNotFound
	}

	return userID, nil
}

func (s *sqlPasswordResetStore) DeleteUserPasswordResets(userID string) error {
	_, err := s.db.Exec("DELETE FROM password_resets WHERE userID = ?;", userID)
	return err
}

func (s *sqlPasswordResetStore) CleanExpired(now time.Time) {
	if err := deleteExpired(s.db, "password_resets", now); err != nil {
		log.Printf("WRN password_resets CleanExpired: %v", err)
	}
}

// fromUnixMilli is the zero time for 0
func fromUnixMilli(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}

	return time.UnixMilli(value)
}

package stores

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

const (
	deviceStatusPending  = "pending"
	deviceStatusApproved = "approved"
	deviceStatusDenied   = "denied"

	deviceColumns = "deviceCodeHash, userCode, clientID, scopes, expiresAt, interval, lastPolled, status, userID, authTime, mfaVerified"
)

type sqlDeviceCodeStore struct {
	db *sql.DB
}

// NewSqliteDeviceCodeStore initializes a DeviceCodeStore in SQLite. The dates
// are unix milliseconds, so they are compared as numbers. Every operation is
// a single conditional statement: it is atomic even with several instances
// sharing the database.
func NewSqliteDeviceCodeStore(db *sql.DB) domain.DeviceCodeStore {
	return &sqlDeviceCodeStore{db: db}
}

func (s *sqlDeviceCodeStore) NewDeviceCode(code domain.DeviceCode) error {
	scopes, err := json.Marshal(nonNil(code.Scopes))
	if err != nil {
		return err
	}

	_, err = s.db.Exec("INSERT INTO device_codes("+deviceColumns+") VALUES(?,?,?,?,?,?,?,?,?,?,?);",
		code.DeviceCodeHash, code.UserCode, code.ClientID, string(scopes), millis(code.ExpiresAt), code.Interval,
		int64(0), deviceStatusPending, "", int64(0), false)
	if err != nil {
		return fmt.Errorf("NewDeviceCode: %w", err)
	}

	return nil
}

func (s *sqlDeviceCodeStore) GetDeviceCodeByUserCode(userCode string, now time.Time) (domain.DeviceCode, error) {
	row := s.db.QueryRow("SELECT "+deviceColumns+" FROM device_codes WHERE userCode = ? AND status = ? AND expiresAt > ?;",
		NormalizeUserCode(userCode), deviceStatusPending, millis(now))
	return scanDeviceCode(row)
}

func (s *sqlDeviceCodeStore) Approve(userCode, userID string, authTime time.Time, mfaVerified bool, now time.Time) error {
	r, err := s.db.Exec("UPDATE device_codes SET status = ?, userID = ?, authTime = ?, mfaVerified = ? WHERE userCode = ? AND status = ? AND expiresAt > ?;",
		deviceStatusApproved, userID, millis(authTime), mfaVerified, NormalizeUserCode(userCode), deviceStatusPending, millis(now))
	if err != nil {
		return fmt.Errorf("Approve: %w", err)
	}

	return expectOneRow(r, "device code")
}

func (s *sqlDeviceCodeStore) Deny(userCode string, now time.Time) error {
	r, err := s.db.Exec("UPDATE device_codes SET status = ? WHERE userCode = ? AND status = ? AND expiresAt > ?;",
		deviceStatusDenied, NormalizeUserCode(userCode), deviceStatusPending, millis(now))
	if err != nil {
		return fmt.Errorf("Deny: %w", err)
	}

	return expectOneRow(r, "device code")
}

func (s *sqlDeviceCodeStore) Poll(deviceCodeHash, clientID string, now time.Time) (domain.DeviceCode, domain.DevicePollResult, error) {
	// the code of another client is not found: it must not be consumed
	row := s.db.QueryRow("SELECT "+deviceColumns+" FROM device_codes WHERE deviceCodeHash = ? AND clientID = ?;", deviceCodeHash, clientID)
	code, err := scanDeviceCode(row)
	if err != nil {
		return domain.DeviceCode{}, 0, err
	}

	var result domain.DevicePollResult
	switch {
	case code.HasExpired(now):
		result = domain.DeviceExpired
	case code.Approved:
		result = domain.DeviceApproved
	case code.Denied:
		result = domain.DeviceDenied
	default:
		return s.pollPending(code, now)
	}

	// consume it: only the request that deletes the row gets the result
	r, err := s.db.Exec("DELETE FROM device_codes WHERE deviceCodeHash = ?;", deviceCodeHash)
	if err != nil {
		return domain.DeviceCode{}, 0, fmt.Errorf("Poll: %w", err)
	}

	if err := expectOneRow(r, "device code"); err != nil {
		return domain.DeviceCode{}, 0, err
	}

	return code, result, nil
}

// pollPending registers the poll of a pending code and increases the interval
// when the device polls too fast (RFC 8628 section 3.5)
func (s *sqlDeviceCodeStore) pollPending(code domain.DeviceCode, now time.Time) (domain.DeviceCode, domain.DevicePollResult, error) {
	tooFast := !code.LastPolled.IsZero() && now.Sub(code.LastPolled) < time.Duration(code.Interval)*time.Second
	if tooFast {
		code.Interval += slowDownIncrement
	}

	// the lastPolled condition makes concurrent polls count only once
	_, err := s.db.Exec("UPDATE device_codes SET lastPolled = ?, interval = ? WHERE deviceCodeHash = ? AND status = ? AND lastPolled = ?;",
		millis(now), code.Interval, code.DeviceCodeHash, deviceStatusPending, millis(code.LastPolled))
	if err != nil {
		return domain.DeviceCode{}, 0, fmt.Errorf("Poll: %w", err)
	}

	if tooFast {
		return code, domain.DeviceSlowDown, nil
	}

	return code, domain.DevicePending, nil
}

func (s *sqlDeviceCodeStore) CleanExpired(now time.Time) {
	if _, err := s.db.Exec("DELETE FROM device_codes WHERE expiresAt <= ?;", millis(now)); err != nil {
		log.Printf("WRN device codes CleanExpired: %v", err)
	}
}

func scanDeviceCode(row scanner) (domain.DeviceCode, error) {
	var (
		code                            domain.DeviceCode
		scopes, status                  string
		expiresAt, lastPolled, authTime int64
	)
	err := row.Scan(&code.DeviceCodeHash, &code.UserCode, &code.ClientID, &scopes, &expiresAt, &code.Interval,
		&lastPolled, &status, &code.UserID, &authTime, &code.MFAVerified)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.DeviceCode{}, errors.New("device code not found")
	}
	if err != nil {
		return domain.DeviceCode{}, err
	}

	if err := json.Unmarshal([]byte(scopes), &code.Scopes); err != nil {
		return domain.DeviceCode{}, fmt.Errorf("device code scopes: %w", err)
	}

	code.ExpiresAt = fromMillis(expiresAt)
	code.LastPolled = fromMillis(lastPolled)
	code.AuthTime = fromMillis(authTime)
	code.Approved = strings.EqualFold(status, deviceStatusApproved)
	code.Denied = strings.EqualFold(status, deviceStatusDenied)
	return code, nil
}

// millis stores a time as unix milliseconds (0 for the zero time)
func millis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}

	return t.UnixMilli()
}

func fromMillis(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}

	return time.UnixMilli(ms)
}

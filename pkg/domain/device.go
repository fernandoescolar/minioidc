package domain

import "time"

// DeviceCode is an in-flight device authorization (RFC 8628)
type DeviceCode struct {
	// DeviceCodeHash is the SHA-256 of the device_code (the device_code is a credential)
	DeviceCodeHash string
	// UserCode is normalized: uppercase letters without separators
	UserCode  string
	ClientID  string
	Scopes    []string
	ExpiresAt time.Time
	// Interval is the minimum seconds between polls. It grows with slow_down.
	Interval   int
	LastPolled time.Time

	Approved bool
	Denied   bool
	// UserID, AuthTime and MFAVerified describe the user who approved it
	UserID      string
	AuthTime    time.Time
	MFAVerified bool
}

// HasExpired returns true if the device code has passed its expiry time
func (d *DeviceCode) HasExpired(now time.Time) bool {
	return !now.Before(d.ExpiresAt)
}

// DevicePollResult is the state of a device code when the device polls
type DevicePollResult int

const (
	DevicePending DevicePollResult = iota
	DeviceSlowDown
	DeviceApproved
	DeviceDenied
	DeviceExpired
)

// DeviceCodeStore keeps the device codes. All the operations are atomic.
type DeviceCodeStore interface {
	// NewDeviceCode stores a device code. It fails if the user code already exists.
	NewDeviceCode(code DeviceCode) error
	// GetDeviceCodeByUserCode returns a copy of a pending device code
	GetDeviceCodeByUserCode(userCode string, now time.Time) (DeviceCode, error)
	// Approve and Deny resolve a pending device code
	Approve(userCode, userID string, authTime time.Time, mfaVerified bool, now time.Time) error
	Deny(userCode string, now time.Time) error
	// Poll registers a poll of the device of the client. Approved, denied and
	// expired codes are consumed: they can only be returned once. The polls of
	// other clients fail without changing the code.
	Poll(deviceCodeHash, clientID string, now time.Time) (DeviceCode, DevicePollResult, error)
	CleanExpired(now time.Time)
}

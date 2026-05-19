package domain

import "time"

// DeviceCode represents an in-flight device authorization flow (RFC 8628).
type DeviceCode struct {
	DeviceCode string
	UserCode   string
	ClientID   string
	Scopes     []string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	LastPolled time.Time
	Interval   int
	Approved   bool
	Denied     bool
	UserID     string
}

// HasExpired returns true if the device code has passed its expiry time.
func (d *DeviceCode) HasExpired() bool {
	return d.ExpiresAt.Before(time.Now())
}

// DeviceCodeStore manages DeviceCode objects.
type DeviceCodeStore interface {
	NewDeviceCode(deviceCode, userCode, clientID string, scopes []string, issuedAt, expiresAt time.Time, interval int) (*DeviceCode, error)
	GetDeviceCodeByCode(deviceCode string) (*DeviceCode, error)
	GetDeviceCodeByUserCode(userCode string) (*DeviceCode, error)
	Approve(deviceCode, userID string) error
	Deny(deviceCode string) error
	UpdatePolled(deviceCode string, lastPolled time.Time) error
	Delete(deviceCode string) error
	CleanExpired()
}

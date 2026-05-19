package stores

import (
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

const (
	deviceCodeCharset = "BCDFGHJKLMNPQRSTVWXZ23456789"
)

type miniDeviceCodeStore struct {
	sync.Map
}

// NewDeviceCodeStore creates an in-memory DeviceCodeStore.
func NewDeviceCodeStore() domain.DeviceCodeStore {
	return &miniDeviceCodeStore{}
}

func (s *miniDeviceCodeStore) NewDeviceCode(deviceCode, userCode, clientID string, scopes []string, issuedAt, expiresAt time.Time, interval int) (*domain.DeviceCode, error) {
	dc := &domain.DeviceCode{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   clientID,
		Scopes:     scopes,
		IssuedAt:   issuedAt,
		ExpiresAt:  expiresAt,
		Interval:   interval,
	}
	s.Map.Store(deviceCode, dc)
	return dc, nil
}

func (s *miniDeviceCodeStore) GetDeviceCodeByCode(deviceCode string) (*domain.DeviceCode, error) {
	v, ok := s.Map.Load(deviceCode)
	if !ok {
		return nil, errors.New("device code not found")
	}
	return v.(*domain.DeviceCode), nil
}

func (s *miniDeviceCodeStore) GetDeviceCodeByUserCode(userCode string) (*domain.DeviceCode, error) {
	var found *domain.DeviceCode
	s.Map.Range(func(_, v any) bool {
		dc := v.(*domain.DeviceCode)
		if dc.UserCode == userCode {
			found = dc
			return false
		}
		return true
	})
	if found == nil {
		return nil, errors.New("device code not found for user code")
	}
	return found, nil
}

func (s *miniDeviceCodeStore) Approve(deviceCode, userID string) error {
	v, ok := s.Map.Load(deviceCode)
	if !ok {
		return errors.New("device code not found")
	}
	dc := v.(*domain.DeviceCode)
	dc.Approved = true
	dc.UserID = userID
	s.Map.Store(deviceCode, dc)
	return nil
}

func (s *miniDeviceCodeStore) Deny(deviceCode string) error {
	v, ok := s.Map.Load(deviceCode)
	if !ok {
		return errors.New("device code not found")
	}
	dc := v.(*domain.DeviceCode)
	dc.Denied = true
	s.Map.Store(deviceCode, dc)
	return nil
}

func (s *miniDeviceCodeStore) UpdatePolled(deviceCode string, lastPolled time.Time) error {
	v, ok := s.Map.Load(deviceCode)
	if !ok {
		return errors.New("device code not found")
	}
	dc := v.(*domain.DeviceCode)
	dc.LastPolled = lastPolled
	s.Map.Store(deviceCode, dc)
	return nil
}

func (s *miniDeviceCodeStore) Delete(deviceCode string) error {
	s.Map.Delete(deviceCode)
	return nil
}

func (s *miniDeviceCodeStore) CleanExpired() {
	s.Map.Range(func(k, v any) bool {
		dc := v.(*domain.DeviceCode)
		if dc.HasExpired() {
			s.Map.Delete(k)
		}
		return true
	})
}

// GenerateUserCode returns a user-friendly 8-character code formatted as XXXX-XXXX,
// using only unambiguous uppercase characters and digits.
func GenerateUserCode() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	n := len(deviceCodeCharset)
	code := make([]byte, 8)
	for i, b := range buf {
		code[i] = deviceCodeCharset[int(b)%n]
	}
	return string(code[:4]) + "-" + string(code[4:]), nil
}

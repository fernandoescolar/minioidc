package stores

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

const (
	// userCodeCharset has no vowels (no words) and no ambiguous characters (RFC 8628 section 6.1)
	userCodeCharset = "BCDFGHJKLMNPQRSTVWXZ"
	userCodeLength  = 8
	// slowDownIncrement is the seconds added to the interval on slow_down (RFC 8628 section 3.5)
	slowDownIncrement = 5
)

type miniDeviceCodeStore struct {
	mu     sync.Mutex
	byHash map[string]*domain.DeviceCode
	byUser map[string]*domain.DeviceCode
}

// NewDeviceCodeStore creates an in-memory DeviceCodeStore
func NewDeviceCodeStore() domain.DeviceCodeStore {
	return &miniDeviceCodeStore{
		byHash: map[string]*domain.DeviceCode{},
		byUser: map[string]*domain.DeviceCode{},
	}
}

func (s *miniDeviceCodeStore) NewDeviceCode(code domain.DeviceCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byUser[code.UserCode]; exists {
		return errors.New("user code already exists")
	}

	stored := code
	stored.Scopes = append([]string{}, code.Scopes...)
	s.byHash[code.DeviceCodeHash] = &stored
	s.byUser[code.UserCode] = &stored
	return nil
}

// pending returns the pending device code of a user code (the lock must be held)
func (s *miniDeviceCodeStore) pending(userCode string, now time.Time) (*domain.DeviceCode, error) {
	code, ok := s.byUser[NormalizeUserCode(userCode)]
	if !ok || code.HasExpired(now) || code.Approved || code.Denied {
		return nil, errors.New("device code not found")
	}

	return code, nil
}

func (s *miniDeviceCodeStore) GetDeviceCodeByUserCode(userCode string, now time.Time) (domain.DeviceCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	code, err := s.pending(userCode, now)
	if err != nil {
		return domain.DeviceCode{}, err
	}

	return copyDeviceCode(code), nil
}

func (s *miniDeviceCodeStore) Approve(userCode, userID string, authTime time.Time, mfaVerified bool, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	code, err := s.pending(userCode, now)
	if err != nil {
		return err
	}

	code.Approved, code.UserID, code.AuthTime, code.MFAVerified = true, userID, authTime, mfaVerified
	return nil
}

func (s *miniDeviceCodeStore) Deny(userCode string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	code, err := s.pending(userCode, now)
	if err != nil {
		return err
	}

	code.Denied = true
	return nil
}

func (s *miniDeviceCodeStore) Poll(deviceCodeHash, clientID string, now time.Time) (domain.DeviceCode, domain.DevicePollResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// the code of another client is not found: it must not be consumed
	code, ok := s.byHash[deviceCodeHash]
	if !ok || code.ClientID != clientID {
		return domain.DeviceCode{}, 0, errors.New("device code not found")
	}

	result := copyDeviceCode(code)
	switch {
	case code.HasExpired(now):
		s.delete(code)
		return result, domain.DeviceExpired, nil
	case code.Approved:
		s.delete(code)
		return result, domain.DeviceApproved, nil
	case code.Denied:
		s.delete(code)
		return result, domain.DeviceDenied, nil
	}

	tooFast := !code.LastPolled.IsZero() && now.Sub(code.LastPolled) < time.Duration(code.Interval)*time.Second
	code.LastPolled = now
	if tooFast {
		code.Interval += slowDownIncrement
		result.Interval = code.Interval
		return result, domain.DeviceSlowDown, nil
	}

	return result, domain.DevicePending, nil
}

func (s *miniDeviceCodeStore) CleanExpired(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, code := range s.byHash {
		if code.HasExpired(now) {
			s.delete(code)
		}
	}
}

func (s *miniDeviceCodeStore) delete(code *domain.DeviceCode) {
	delete(s.byHash, code.DeviceCodeHash)
	delete(s.byUser, code.UserCode)
}

func copyDeviceCode(code *domain.DeviceCode) domain.DeviceCode {
	c := *code
	c.Scopes = append([]string{}, code.Scopes...)
	return c
}

// GenerateUserCode returns a random user code of 8 characters (about 34.5 bits),
// without modulo bias. It is normalized: FormatUserCode adds the separator.
func GenerateUserCode() (string, error) {
	max := big.NewInt(int64(len(userCodeCharset)))
	code := make([]byte, userCodeLength)
	for i := range code {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		code[i] = userCodeCharset[n.Int64()]
	}

	return string(code), nil
}

// FormatUserCode shows a normalized user code as XXXX-XXXX
func FormatUserCode(code string) string {
	if len(code) != userCodeLength {
		return code
	}

	return code[:4] + "-" + code[4:]
}

// NormalizeUserCode makes the user input comparable: uppercase and without
// separators or spaces (RFC 8628 section 6.1)
func NormalizeUserCode(input string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(input) {
		if strings.ContainsRune(userCodeCharset, r) {
			b.WriteRune(r)
		}
	}

	return b.String()
}

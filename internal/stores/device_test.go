package stores

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fernandoescolar/minioidc/internal/db"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

func TestUserCodes(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		code, err := GenerateUserCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != userCodeLength || strings.Trim(code, userCodeCharset) != "" {
			t.Fatalf("Unexpected user code %q", code)
		}
		seen[code] = true
	}
	if len(seen) < 999 {
		t.Fatalf("Expected random user codes, got %d different", len(seen))
	}

	if NormalizeUserCode(" bcdf-ghjk ") != "BCDFGHJK" || FormatUserCode("BCDFGHJK") != "BCDF-GHJK" {
		t.Fatal("Unexpected user code normalization")
	}
}

func deviceCodeStores(t *testing.T) map[string]domain.DeviceCodeStore {
	t.Helper()
	database, err := db.NewSqliteDB(t.TempDir() + "/devices.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	return map[string]domain.DeviceCodeStore{
		"memory": NewDeviceCodeStore(),
		"sqlite": NewSqliteDeviceCodeStore(database),
	}
}

func TestDeviceCodeStore(t *testing.T) {
	for name, s := range deviceCodeStores(t) {
		t.Run(name, func(t *testing.T) { testDeviceCodeStore(t, s) })
	}
}

// an approved code polled concurrently gives the tokens only once
func TestDeviceCodeStoreConcurrentPolls(t *testing.T) {
	for name, s := range deviceCodeStores(t) {
		t.Run(name, func(t *testing.T) {
			now := time.Now()
			if err := s.NewDeviceCode(domain.DeviceCode{DeviceCodeHash: "h", UserCode: "BCDFGHJK", ClientID: "tv", ExpiresAt: now.Add(time.Minute), Interval: 5}); err != nil {
				t.Fatal(err)
			}
			if err := s.Approve("BCDFGHJK", "user", now, false, now); err != nil {
				t.Fatal(err)
			}

			var (
				wg       sync.WaitGroup
				approved atomic.Int32
			)
			for i := 0; i < 20; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if _, result, err := s.Poll("h", "tv", now); err == nil && result == domain.DeviceApproved {
						approved.Add(1)
					}
				}()
			}
			wg.Wait()

			if approved.Load() != 1 {
				t.Fatalf("Expected the approved code to be returned once, got %d", approved.Load())
			}
		})
	}
}

func testDeviceCodeStore(t *testing.T, s domain.DeviceCodeStore) {
	now := time.Now()
	code := domain.DeviceCode{DeviceCodeHash: "h1", UserCode: "BCDFGHJK", ClientID: "tv", ExpiresAt: now.Add(time.Minute), Interval: 5}
	if err := s.NewDeviceCode(code); err != nil {
		t.Fatal(err)
	}
	if err := s.NewDeviceCode(domain.DeviceCode{DeviceCodeHash: "h2", UserCode: "BCDFGHJK"}); err == nil {
		t.Fatal("Expected duplicated user codes to be rejected")
	}

	if _, err := s.GetDeviceCodeByUserCode("bcdf-ghjk", now); err != nil {
		t.Fatalf("Expected the user code to be found normalized: %v", err)
	}

	// the polls of other clients do not change the code
	if _, _, err := s.Poll("h1", "other", now); err == nil {
		t.Fatal("Expected another client not to find the code")
	}

	if _, result, _ := s.Poll("h1", "tv", now); result != domain.DevicePending {
		t.Fatalf("Expected pending, got %v", result)
	}
	if code, result, _ := s.Poll("h1", "tv", now.Add(time.Second)); result != domain.DeviceSlowDown || code.Interval != 10 {
		t.Fatalf("Expected slow_down with 10 seconds, got %v %d", result, code.Interval)
	}

	if err := s.Approve("BCDFGHJK", "user", now, true, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Deny("BCDFGHJK", now); err == nil {
		t.Fatal("Expected a resolved code not to change")
	}

	if code, result, _ := s.Poll("h1", "tv", now.Add(time.Minute/2)); result != domain.DeviceApproved || code.UserID != "user" || !code.MFAVerified {
		t.Fatalf("Expected approved, got %v %+v", result, code)
	}
	if _, _, err := s.Poll("h1", "tv", now.Add(time.Minute/2)); err == nil {
		t.Fatal("Expected the approved code to be consumed")
	}

	// expiration
	_ = s.NewDeviceCode(domain.DeviceCode{DeviceCodeHash: "h3", UserCode: "CDFGHJKL", ClientID: "tv", ExpiresAt: now.Add(time.Minute)})
	if _, err := s.GetDeviceCodeByUserCode("CDFGHJKL", now.Add(2*time.Minute)); err == nil {
		t.Fatal("Expected an expired user code not to be found")
	}
	if _, result, _ := s.Poll("h3", "tv", now.Add(2*time.Minute)); result != domain.DeviceExpired {
		t.Fatalf("Expected expired, got %v", result)
	}
}

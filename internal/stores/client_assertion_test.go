package stores

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fernandoescolar/minioidc/internal/db"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

func clientAssertionStores(t *testing.T) map[string]domain.ClientAssertionStore {
	t.Helper()
	database, err := db.NewSqliteDB(t.TempDir() + "/assertions.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	return map[string]domain.ClientAssertionStore{
		"memory": NewClientAssertionStore(),
		"sqlite": NewSqliteClientAssertionStore(database),
	}
}

func TestClientAssertionStore(t *testing.T) {
	for name, store := range clientAssertionStores(t) {
		t.Run(name, func(t *testing.T) {
			now := time.Now()
			expiresAt := now.Add(time.Minute)

			if ok, err := store.Use("client:jti", expiresAt, now); !ok || err != nil {
				t.Fatalf("Expected the first use to be valid: %v", err)
			}

			if ok, _ := store.Use("client:jti", expiresAt, now.Add(30*time.Second)); ok {
				t.Fatal("Expected the replay to be rejected")
			}

			if ok, _ := store.Use("client:other", expiresAt, now); !ok {
				t.Fatal("Expected other assertions to be valid")
			}

			// after the expiration, the assertion itself is rejected by its exp
			if ok, _ := store.Use("client:jti", now.Add(3*time.Minute), now.Add(2*time.Minute)); !ok {
				t.Fatal("Expected an expired entry to be replaced")
			}

			store.CleanExpired(now.Add(time.Hour))
			if ok, _ := store.Use("client:jti", now.Add(2*time.Hour), now.Add(time.Hour)); !ok {
				t.Fatal("Expected the entries to be cleaned")
			}
		})
	}
}

func TestClientAssertionStoreConcurrentUse(t *testing.T) {
	for name, store := range clientAssertionStores(t) {
		t.Run(name, func(t *testing.T) {
			now := time.Now()
			var valid atomic.Int32
			var wg sync.WaitGroup
			for i := 0; i < 20; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if ok, err := store.Use("client:concurrent", now.Add(time.Minute), now); ok && err == nil {
						valid.Add(1)
					}
				}()
			}
			wg.Wait()

			if valid.Load() != 1 {
				t.Fatalf("Expected exactly one valid use, got %d", valid.Load())
			}
		})
	}
}

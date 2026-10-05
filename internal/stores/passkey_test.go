package stores

import (
	"testing"
	"time"

	"github.com/fernandoescolar/minioidc/internal/db"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

func TestPasskeyStores(t *testing.T) {
	database, err := db.NewSqliteDB(t.TempDir() + "/passkeys.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	now := time.UnixMilli(time.Now().UnixMilli())
	for name, store := range map[string]domain.PasskeyStore{
		"memory": NewPasskeyStore(),
		"sqlite": NewSqlitePasskeyStore(database),
	} {
		t.Run(name, func(t *testing.T) {
			second := domain.Passkey{ID: "b", UserID: "alice", Name: "phone", Credential: []byte(`{"n":2}`), CreatedAt: now.Add(time.Minute)}
			first := domain.Passkey{ID: "a", UserID: "alice", Name: "laptop", Credential: []byte(`{"n":1}`), CreatedAt: now}
			other := domain.Passkey{ID: "c", UserID: "bob", Name: "key", Credential: []byte(`{}`), CreatedAt: now}
			for _, p := range []domain.Passkey{second, first, other} {
				if err := store.AddPasskey(p); err != nil {
					t.Fatal(err)
				}
			}
			if err := store.AddPasskey(first); err == nil {
				t.Error("Expected an error adding a passkey twice")
			}

			// the oldest first
			list, err := store.ListPasskeys("alice")
			if err != nil || len(list) != 2 || list[0].ID != "a" || list[1].ID != "b" {
				t.Fatalf("Unexpected passkeys: %+v %v", list, err)
			}
			if !list[0].CreatedAt.Equal(now) || !list[0].LastUsedAt.IsZero() || string(list[0].Credential) != `{"n":1}` {
				t.Errorf("Unexpected passkey: %+v", list[0])
			}

			usedAt := now.Add(time.Hour)
			if err := store.UsePasskey("a", []byte(`{"n":3}`), usedAt); err != nil {
				t.Fatal(err)
			}
			got, err := store.GetPasskey("a")
			if err != nil || string(got.Credential) != `{"n":3}` || !got.LastUsedAt.Equal(usedAt) {
				t.Errorf("Expected the updated credential: %+v %v", got, err)
			}

			// the users only change their passkeys
			if err := store.RenamePasskey("bob", "a", "mine"); err == nil {
				t.Error("Expected an error renaming the passkey of another user")
			}
			if err := store.DeletePasskey("bob", "a"); err == nil {
				t.Error("Expected an error deleting the passkey of another user")
			}
			if err := store.RenamePasskey("alice", "a", "work laptop"); err != nil {
				t.Fatal(err)
			}
			if got, _ := store.GetPasskey("a"); got.Name != "work laptop" {
				t.Errorf("Expected the new name, got %q", got.Name)
			}

			if err := store.DeletePasskey("alice", "b"); err != nil {
				t.Fatal(err)
			}
			if err := store.DeleteUserPasskeys("alice"); err != nil {
				t.Fatal(err)
			}
			if list, _ := store.ListPasskeys("alice"); len(list) != 0 {
				t.Errorf("Expected no passkeys, got %+v", list)
			}
			if _, err := store.GetPasskey("c"); err != nil {
				t.Errorf("Expected the passkeys of other users: %v", err)
			}
		})
	}
}

package stores

import (
	"testing"

	"github.com/fernandoescolar/minioidc/internal/db"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// a user can only delete their own MFA codes
func TestDeleteMFACodeChecksTheOwner(t *testing.T) {
	database, err := db.NewSqliteDB(t.TempDir() + "/mfa.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	users := NewUserStore()
	alice, _ := users.NewUser(domain.UserData{Subject: "alice", PreferredUsername: "alice"})

	for name, store := range map[string]domain.MFACodeStore{
		"memory": NewMFACodeStore(users),
		"sqlite": NewSqliteMFACodeStore(database, users),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := store.NewMFACode("code-"+name, alice, "SECRET", "totp"); err != nil {
				t.Fatal(err)
			}

			if err := store.DeleteMFACode("mallory", "code-"+name); err == nil {
				t.Fatal("Expected another user not to delete the code")
			}
			if has, _ := store.UserHasMFACodes("alice"); !has {
				t.Fatal("Expected the code to be kept")
			}

			if err := store.DeleteMFACode("alice", "code-"+name); err != nil {
				t.Fatalf("Expected the owner to delete the code: %v", err)
			}
		})
	}
}

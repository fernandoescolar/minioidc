package stores

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fernandoescolar/minioidc/internal/db"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

func TestUserStateStores(t *testing.T) {
	database, err := db.NewSqliteDB(t.TempDir() + "/states.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	now := time.UnixMilli(time.Now().UnixMilli())
	for name, store := range map[string]domain.UserStateStore{
		"memory": NewUserStateStore(),
		"sqlite": NewSqliteUserStateStore(database),
	} {
		t.Run(name, func(t *testing.T) {
			// the users without a state can sign in
			state, err := store.GetUserState("alice")
			if err != nil || state.Subject != "alice" || state.CanSignIn(now) != nil {
				t.Fatalf("Unexpected empty state: %+v %v", state, err)
			}

			saved := domain.UserState{
				Subject: "alice", Disabled: true, DisabledReason: "why", DisabledAt: now, DisabledBy: "root",
				Locked: true, LockedUntil: now.Add(time.Hour), LockReason: "later", LockedAt: now, LockedBy: "root",
				PasswordChangeRequired: true,
			}
			if err := store.SaveUserState(saved); err != nil {
				t.Fatal(err)
			}
			state, err = store.GetUserState("alice")
			if err != nil || state != saved {
				t.Fatalf("Expected %+v, got %+v %v", saved, state, err)
			}
			if state.CanSignIn(now) != domain.ErrAccountDisabled {
				t.Error("Expected a disabled account")
			}

			state.Disabled = false
			if err := store.SaveUserState(state); err != nil {
				t.Fatal(err)
			}
			if err := domain.CheckSignIn(store, "alice", now); err != domain.ErrAccountLocked {
				t.Errorf("Expected a locked account, got %v", err)
			}
			if err := domain.CheckSignIn(store, "alice", now.Add(2*time.Hour)); err != nil {
				t.Errorf("Expected the lock ended, got %v", err)
			}

			if err := store.DeleteUserState("alice"); err != nil {
				t.Fatal(err)
			}
			if state, _ := store.GetUserState("alice"); state.PasswordChangeRequired {
				t.Errorf("Expected an empty state, got %+v", state)
			}
		})
	}
}

func TestPasswordResetStores(t *testing.T) {
	database, err := db.NewSqliteDB(t.TempDir() + "/resets.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	now := time.Now()
	for name, store := range map[string]domain.PasswordResetStore{
		"memory": NewPasswordResetStore(),
		"sqlite": NewSqlitePasswordResetStore(database),
	} {
		t.Run(name, func(t *testing.T) {
			if err := store.NewPasswordReset("first", "alice", now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			if user, err := store.CheckPasswordReset("first", now); err != nil || user != "alice" {
				t.Fatalf("Expected the reset of alice, got %q %v", user, err)
			}

			// a new link replaces the previous one
			if err := store.NewPasswordReset("second", "alice", now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			if _, err := store.CheckPasswordReset("first", now); err == nil {
				t.Error("Expected the first link replaced")
			}

			// the links expire
			if _, err := store.CheckPasswordReset("second", now.Add(2*time.Hour)); err == nil {
				t.Error("Expected an expired link")
			}

			// a link is used once, even by concurrent requests
			var used atomic.Int32
			var wg sync.WaitGroup
			for range 10 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if user, err := store.TakePasswordReset("second", now); err == nil && user == "alice" {
						used.Add(1)
					}
				}()
			}
			wg.Wait()
			if used.Load() != 1 {
				t.Errorf("Expected the link used once, got %d", used.Load())
			}

			if err := store.NewPasswordReset("third", "bob", now.Add(-time.Minute)); err != nil {
				t.Fatal(err)
			}
			store.CleanExpired(now)
			if err := store.NewPasswordReset("fourth", "bob", now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			if err := store.DeleteUserPasswordResets("bob"); err != nil {
				t.Fatal(err)
			}
			if _, err := store.CheckPasswordReset("fourth", now); err == nil {
				t.Error("Expected the links of bob deleted")
			}
		})
	}
}

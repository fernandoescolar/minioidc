package stores

import (
	"testing"
	"time"

	"github.com/fernandoescolar/minioidc/internal/db"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

func TestEventStores(t *testing.T) {
	database, err := db.NewSqliteDB(t.TempDir() + "/events.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	now := time.UnixMilli(time.Now().UnixMilli())
	for name, store := range map[string]domain.EventStore{
		"memory": NewEventStore(),
		"sqlite": NewSqliteEventStore(database),
	} {
		t.Run(name, func(t *testing.T) {
			for _, e := range []domain.Event{
				{Time: now.Add(-3 * time.Hour), Type: domain.EventLoginPassword, Result: domain.ResultSuccess, UserID: "1", Username: "alice", IP: "10.0.0.1"},
				{Time: now.Add(-2 * time.Hour), Type: domain.EventLoginPassword, Result: domain.ResultFailure, Username: "Alice", Detail: "invalid credentials"},
				{Time: now.Add(-time.Hour), Type: domain.EventAdminState, Result: domain.ResultSuccess, UserID: "2", Username: "bob", Actor: "alice"},
				{Time: now, Type: domain.EventLogout, Result: domain.ResultSuccess, UserID: "1", Username: "alice", ClientID: "app_1"},
			} {
				if err := store.AddEvent(e); err != nil {
					t.Fatal(err)
				}
			}

			count := func(filter domain.EventFilter) int {
				t.Helper()
				events, err := store.ListEvents(filter)
				if err != nil {
					t.Fatal(err)
				}
				total, err := store.CountEvents(filter)
				if err != nil {
					t.Fatal(err)
				}
				if filter.Limit == 0 && total != len(events) {
					t.Errorf("%+v: count %d, list %d", filter, total, len(events))
				}
				return len(events)
			}

			for expected, filter := range map[int]domain.EventFilter{
				4: {},
				2: {TypePrefix: "login."},
				1: {Result: domain.ResultFailure},
				3: {UserID: "1", Username: "alice"}, // with the failed login of the unknown subject
			} {
				if got := count(filter); got != expected {
					t.Errorf("%+v: expected %d events, got %d", filter, expected, got)
				}
			}
			for filter, expected := range map[*domain.EventFilter]int{
				{UserID: "1"}:                       2,
				{Search: "ALICE"}:                   4, // the username, or the actor
				{Search: "10.0.0"}:                  1,
				{Search: "p_1"}:                     1, // the _ is not a wildcard
				{Search: "%"}:                       0,
				{Since: now.Add(-90 * time.Minute)}: 2,
				{Until: now.Add(-90 * time.Minute)}: 2,
				{Limit: 1}:                          1,
			} {
				if got := count(*filter); got != expected {
					t.Errorf("%+v: expected %d events, got %d", *filter, expected, got)
				}
			}

			// the newest first, and the pages
			events, _ := store.ListEvents(domain.EventFilter{Limit: 2})
			if len(events) != 2 || events[0].Type != domain.EventLogout || events[0].ClientID != "app_1" || !events[0].Time.Equal(now) {
				t.Fatalf("Unexpected events: %+v", events)
			}
			older, _ := store.ListEvents(domain.EventFilter{Before: events[1].ID})
			if len(older) != 2 || older[0].ID >= events[1].ID {
				t.Errorf("Unexpected older events: %+v", older)
			}

			last, ok, err := store.LastEvent("1", "login.", domain.ResultSuccess)
			if err != nil || !ok || !last.Time.Equal(now.Add(-3*time.Hour)) {
				t.Errorf("Unexpected last login: %+v %v %v", last, ok, err)
			}
			if _, ok, _ := store.LastEvent("3", "login.", domain.ResultSuccess); ok {
				t.Error("Expected no last login")
			}

			if err := store.DeleteEventsBefore(now.Add(-90 * time.Minute)); err != nil {
				t.Fatal(err)
			}
			if got := count(domain.EventFilter{}); got != 2 {
				t.Errorf("Expected the old events removed, got %d", got)
			}
		})
	}
}

// the memory store keeps the last events
func TestMemoryEventStoreLimit(t *testing.T) {
	store := NewEventStore()
	for i := range maxMemoryEvents + 10 {
		_ = store.AddEvent(domain.Event{Type: domain.EventLogout, Detail: string(rune('a' + i%26))})
	}

	events, _ := store.ListEvents(domain.EventFilter{})
	if len(events) != maxMemoryEvents || events[0].ID != maxMemoryEvents+10 {
		t.Errorf("Expected the last %d events, got %d (newest %d)", maxMemoryEvents, len(events), events[0].ID)
	}
}

package stores

import (
	"testing"
	"time"

	"github.com/fernandoescolar/minioidc/internal/db"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

func TestGroupStores(t *testing.T) {
	database, err := db.NewSqliteDB(t.TempDir() + "/groups.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	created := time.UnixMilli(time.Now().UnixMilli())
	for name, store := range map[string]domain.GroupStore{
		"memory": NewGroupStore(),
		"sqlite": NewSqliteGroupStore(database),
	} {
		t.Run(name, func(t *testing.T) {
			for _, g := range []domain.Group{{Name: "ops", CreatedAt: created}, {Name: "devs", Description: "Developers", CreatedAt: created}} {
				if err := store.SaveGroup(g); err != nil {
					t.Fatal(err)
				}
			}

			// the description changes, the creation date is kept
			if err := store.SaveGroup(domain.Group{Name: "devs", Description: "Dev team"}); err != nil {
				t.Fatal(err)
			}
			g, ok, err := store.GetGroup("devs")
			if err != nil || !ok || g.Description != "Dev team" || !g.CreatedAt.Equal(created) {
				t.Errorf("Unexpected group: %+v %v %v", g, ok, err)
			}

			if err := store.RenameGroup("devs", "developers"); err != nil {
				t.Fatal(err)
			}
			groups, err := store.ListGroups()
			if err != nil || len(groups) != 2 || groups[0].Name != "developers" || groups[1].Name != "ops" {
				t.Errorf("Unexpected groups: %+v %v", groups, err)
			}

			if err := store.DeleteGroup("ops"); err != nil {
				t.Fatal(err)
			}
			if _, ok, _ := store.GetGroup("ops"); ok {
				t.Error("Expected the group deleted")
			}
		})
	}
}

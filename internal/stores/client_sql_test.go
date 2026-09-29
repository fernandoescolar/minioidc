package stores

import (
	"testing"

	"github.com/fernandoescolar/minioidc/internal/db"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

func TestSqliteClientStoreKeepsAllTheProperties(t *testing.T) {
	database, err := db.NewSqliteDB(t.TempDir() + "/clients.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	store := NewSqliteClientStore(database, "0123456789abcdefghijklmnopqrstuvwxyz")
	data := domain.ClientData{
		ID:                      "tv",
		RedirectURIs:            []string{"https://tv.example.com/callback"},
		PostLogoutRedirectURIs:  []string{"https://tv.example.com/"},
		TokenEndpointAuthMethod: domain.AuthMethodNone,
		GrantTypes:              []string{domain.GrantTypeDeviceCode, domain.GrantTypeRefreshToken},
	}
	if _, err := store.NewClient(data); err != nil {
		t.Fatal(err)
	}

	client, err := store.GetClientByID("tv")
	if err != nil {
		t.Fatal(err)
	}

	if !client.GrantTypeAllowed(domain.GrantTypeDeviceCode) || client.GrantTypeAllowed(domain.GrantTypeAuthorizationCode) {
		t.Fatalf("Expected the grant types to be kept: %+v", client.Data().GrantTypes)
	}

	stored := client.Data()
	if len(stored.PostLogoutRedirectURIs) != 1 || stored.TokenEndpointAuthMethod != domain.AuthMethodNone {
		t.Fatalf("Unexpected client: %+v", stored)
	}

	// a client without grant types keeps the defaults
	data.ID, data.GrantTypes = "web", nil
	if _, err := store.NewClient(data); err != nil {
		t.Fatal(err)
	}
	if web, _ := store.GetClientByID("web"); !web.GrantTypeAllowed(domain.GrantTypeAuthorizationCode) {
		t.Fatal("Expected the default grant types")
	}
}

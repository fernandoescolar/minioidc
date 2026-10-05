package api_test

import (
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/api"
)

type groupDTO struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Members     int      `json:"members"`
	Admin       bool     `json:"admin"`
	Clients     []string `json:"clients"`
	Defined     bool     `json:"defined"`
}

func (a *adminClient) groups() map[string]groupDTO {
	a.t.Helper()
	var list []groupDTO
	a.call(http.MethodGet, "/groups", nil, http.StatusOK, &list)
	groups := map[string]groupDTO{}
	for _, g := range list {
		groups[g.Name] = g
	}
	return groups
}

func (a *adminClient) userGroups(subject string) []string {
	a.t.Helper()
	var user struct {
		Groups []string `json:"groups"`
	}
	a.call(http.MethodGet, "/users/"+subject, nil, http.StatusOK, &user)
	return user.Groups
}

func TestAdminManagesGroups(t *testing.T) {
	s, _ := newAdminServer(t)
	admin := s.loginAs(t, username)

	admin.call(http.MethodPost, "/groups", map[string]string{"name": " devs ", "description": "The developers"}, http.StatusCreated, nil)
	admin.call(http.MethodPost, "/groups", map[string]string{"name": "DEVS"}, http.StatusConflict, nil)
	admin.call(http.MethodPost, "/groups", map[string]string{"name": "Admin"}, http.StatusConflict, nil)
	for _, name := range []string{"", "a/b", "a,b", string(make([]byte, 65))} {
		admin.call(http.MethodPost, "/groups", map[string]string{"name": name}, http.StatusBadRequest, nil)
	}

	admin.call(http.MethodPost, "/groups/devs/members", map[string][]string{"subjects": {"2"}}, http.StatusNoContent, nil)
	// adding it twice changes nothing
	admin.call(http.MethodPost, "/groups/devs/members", map[string][]string{"subjects": {"2"}}, http.StatusNoContent, nil)
	if groups := admin.userGroups("2"); !slices.Equal(groups, []string{"devs"}) {
		t.Errorf("Expected the user in the group, got %v", groups)
	}

	groups := admin.groups()
	if g := groups["devs"]; !g.Defined || g.Members != 1 || g.Description != "The developers" || g.Admin {
		t.Errorf("Unexpected group: %+v", g)
	}
	if g := groups["admin"]; !g.Admin || g.Members != 1 {
		t.Errorf("Unexpected admin group: %+v", g)
	}

	var members []struct {
		Subject string `json:"subject"`
	}
	admin.call(http.MethodGet, "/groups/devs/members", nil, http.StatusOK, &members)
	if len(members) != 1 || members[0].Subject != "2" {
		t.Errorf("Unexpected members: %+v", members)
	}

	// the rename changes the users
	admin.call(http.MethodPut, "/groups/devs", map[string]string{"name": "developers", "description": "Dev team"}, http.StatusNoContent, nil)
	if groups := admin.userGroups("2"); !slices.Equal(groups, []string{"developers"}) {
		t.Errorf("Expected the group renamed in the user, got %v", groups)
	}
	if g, ok := admin.groups()["developers"]; !ok || g.Description != "Dev team" || g.Members != 1 {
		t.Errorf("Unexpected renamed group: %+v", g)
	}

	// the admin group is protected
	admin.call(http.MethodPut, "/groups/admin", map[string]string{"name": "root"}, http.StatusBadRequest, nil)
	admin.call(http.MethodPut, "/groups/developers", map[string]string{"name": "admin"}, http.StatusBadRequest, nil)
	admin.call(http.MethodDelete, "/groups/admin", nil, http.StatusBadRequest, nil)
	admin.call(http.MethodDelete, "/groups/admin/members/1", nil, http.StatusBadRequest, nil)

	admin.call(http.MethodDelete, "/groups/developers/members/2", nil, http.StatusNoContent, nil)
	admin.call(http.MethodDelete, "/groups/developers/members/2", nil, http.StatusNotFound, nil)
	admin.call(http.MethodPost, "/groups/developers/members", map[string][]string{"subjects": {"2"}}, http.StatusNoContent, nil)
	admin.call(http.MethodDelete, "/groups/developers", nil, http.StatusNoContent, nil)
	if groups := admin.userGroups("2"); len(groups) != 0 {
		t.Errorf("Expected the group removed from the user, got %v", groups)
	}
	if _, ok := admin.groups()["developers"]; ok {
		t.Error("Expected the group deleted")
	}

	// a new administrator needs a recent login
	s.clock.Advance(11 * time.Minute)
	resp, body := admin.do(http.MethodPost, "/groups/admin/members", map[string][]string{"subjects": {"2"}}, true)
	expectStatus(t, resp, body, http.StatusForbidden)
	admin = s.loginAs(t, username)
	admin.call(http.MethodPost, "/groups/admin/members", map[string][]string{"subjects": {"2"}}, http.StatusNoContent, nil)

	var events eventPage
	admin.call(http.MethodGet, "/events?type=admin.group", nil, http.StatusOK, &events)
	if len(events.Events) != 7 {
		t.Errorf("Expected the group changes in the activity log, got %d", len(events.Events))
	}
}

// withAllowedGroups restricts the confidential client to the devs group
func withAllowedGroups(b *api.Builder) {
	b.Clients[0].AllowedGroups = []string{"devs"}
	b.Clients[0].GrantTypes = []string{"authorization_code", "refresh_token", "password"}
	b.AllowPasswordGrant = true
}

func TestClientAllowedGroups(t *testing.T) {
	s, _ := newAdminServer(t, withAllowedGroups)
	admin := s.loginAs(t, username)
	c := browser(t)

	// the user is not in the group: the client gets access_denied
	resp, body := get(t, c, s.url(authorizePath(clientID, nil)))
	resp, body = s.login(t, c, s.resolve(t, resp), "other", password)
	expectStatus(t, resp, body, http.StatusFound)
	resp, _ = get(t, c, s.resolve(t, resp))
	expectCallbackError(t, resp, "access_denied")
	resp, body = s.passwordGrant(t, "other", password)
	expectError(t, resp, body, http.StatusBadRequest, "invalid_grant")

	// the other clients are not restricted
	resp, _ = get(t, c, s.url(authorizePath(otherClientID, nil)))
	if resp.StatusCode != http.StatusFound || callbackParams(t, resp).Get("code") == "" {
		t.Fatalf("Expected a code for the other client, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	// a member of the group can use it
	admin.call(http.MethodPost, "/groups/devs/members", map[string][]string{"subjects": {"2"}}, http.StatusNoContent, nil)
	resp, _ = get(t, c, s.url(authorizePath(clientID, url.Values{"scope": {"openid offline_access"}})))
	tk := s.exchangeCode(t, callbackParams(t, resp).Get("code"))
	resp, body = s.passwordGrant(t, "other", password)
	expectStatus(t, resp, body, http.StatusOK)

	// the groups of the client follow the renames
	admin.call(http.MethodPut, "/groups/devs", map[string]string{"name": "developers"}, http.StatusNoContent, nil)
	var client struct {
		AllowedGroups []string `json:"allowed_groups"`
	}
	admin.call(http.MethodGet, "/clients/"+clientID, nil, http.StatusOK, &client)
	if !slices.Equal(client.AllowedGroups, []string{"developers"}) {
		t.Errorf("Expected the group renamed in the client, got %v", client.AllowedGroups)
	}
	if g := admin.groups()["developers"]; !slices.Equal(g.Clients, []string{clientID}) {
		t.Errorf("Expected the client in the group, got %+v", g)
	}

	// a group of a client cannot be deleted: the client would be open to all the users
	admin.call(http.MethodDelete, "/groups/developers", nil, http.StatusConflict, nil)

	// out of the group, the refresh token stops working
	admin.call(http.MethodDelete, "/groups/developers/members/2", nil, http.StatusNoContent, nil)
	resp, body = s.refresh(http.DefaultClient, t, tk.RefreshToken)
	expectError(t, resp, body, http.StatusBadRequest, "invalid_grant")

	var events eventPage
	admin.call(http.MethodGet, "/events?type=login.denied", nil, http.StatusOK, &events)
	if len(events.Events) != 2 || events.Events[0].ClientID != clientID || events.Events[0].Username != "other" {
		t.Errorf("Expected the denied sign ins in the activity log: %+v", events.Events)
	}
}

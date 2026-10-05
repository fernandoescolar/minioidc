package api_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/fernandoescolar/minioidc/pkg/api"
)

type adminClient struct {
	t    *testing.T
	s    *testServer
	http *http.Client
}

func withAdmin(database string) func(*api.Builder) {
	return func(b *api.Builder) {
		b.UseSQLite(database, api.All)
		b.AdminEnabled = true
		b.Users[0].Groups = []string{"admin"}
	}
}

func newAdminServer(t *testing.T, options ...func(*api.Builder)) (*testServer, string) {
	t.Helper()
	database := t.TempDir() + "/admin.sqlite3"
	return newTestServer(t, false, append([]func(*api.Builder){withAdmin(database)}, options...)...), database
}

func (s *testServer) loginAs(t *testing.T, user string) *adminClient {
	t.Helper()
	c := browser(t)
	resp, body := s.login(t, c, s.url("/login"), user, password)
	expectStatus(t, resp, body, http.StatusFound)
	return &adminClient{t: t, s: s, http: c}
}

func (a *adminClient) do(method, path string, body interface{}, csrf bool) (*http.Response, string) {
	a.t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			a.t.Fatal(err)
		}
		reader = strings.NewReader(string(data))
	}

	req, err := http.NewRequest(method, a.s.url("/admin/api"+path), reader)
	if err != nil {
		a.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if csrf {
		req.Header.Set("X-Minioidc-Admin", "1")
	}

	return do(a.t, a.http, req)
}

func (a *adminClient) call(method, path string, body interface{}, status int, result interface{}) {
	a.t.Helper()
	resp, text := a.do(method, path, body, true)
	expectStatus(a.t, resp, text, status)
	if result != nil {
		if err := json.Unmarshal([]byte(text), result); err != nil {
			a.t.Fatalf("invalid JSON %s: %v", text, err)
		}
	}
}

// listUsers reads the first page of the users
func (a *adminClient) listUsers(result interface{}) {
	a.t.Helper()
	var page struct {
		Users json.RawMessage `json:"users"`
	}
	a.call(http.MethodGet, "/users", nil, http.StatusOK, &page)
	if err := json.Unmarshal(page.Users, result); err != nil {
		a.t.Fatalf("invalid users %s: %v", page.Users, err)
	}
}

func TestAdminRequiresAnAdministrator(t *testing.T) {
	s, _ := newAdminServer(t)

	// anonymous
	anonymous := &adminClient{t: t, s: s, http: browser(t)}
	resp, body := anonymous.do(http.MethodGet, "/users", nil, false)
	expectStatus(t, resp, body, http.StatusUnauthorized)

	resp, _ = get(t, browser(t), s.url("/admin/"))
	expectLoginRedirect(t, resp)

	// a user that is not an administrator
	user := s.loginAs(t, "other")
	resp, body = user.do(http.MethodGet, "/users", nil, false)
	expectStatus(t, resp, body, http.StatusForbidden)
	resp, body = get(t, user.http, s.url("/admin/"))
	expectStatus(t, resp, body, http.StatusForbidden)

	// an administrator
	admin := s.loginAs(t, username)
	resp, body = get(t, admin.http, s.url("/admin/"))
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, `id="root"`) && !strings.Contains(body, "has not been built") {
		t.Errorf("Expected the admin web: %s", body)
	}

	var info struct {
		UsersReadonly bool `json:"users_readonly"`
		Me            struct {
			Subject string `json:"subject"`
		} `json:"me"`
	}
	admin.call(http.MethodGet, "/info", nil, http.StatusOK, &info)
	if info.UsersReadonly || info.Me.Subject != "1" {
		t.Errorf("Unexpected info: %+v", info)
	}

	// the changes require the CSRF header
	resp, body = admin.do(http.MethodPost, "/maintenance/purge", nil, false)
	expectStatus(t, resp, body, http.StatusForbidden)
	admin.call(http.MethodPost, "/maintenance/purge", nil, http.StatusNoContent, nil)
}

func TestAdminManagesUsers(t *testing.T) {
	s, _ := newAdminServer(t)
	admin := s.loginAs(t, username)

	var users []map[string]interface{}
	admin.listUsers(&users)
	if len(users) != 2 {
		t.Fatalf("Expected the 2 users of the configuration: %v", users)
	}

	newUser := map[string]interface{}{
		"preferred_username": "new", "email": "new@mail.test", "password": "new-password", "groups": []string{"dev", "dev", " "},
	}
	var created map[string]interface{}
	admin.call(http.MethodPost, "/users", newUser, http.StatusCreated, &created)
	subject := created["subject"].(string)
	if subject == "" || len(created["groups"].([]interface{})) != 1 || created["has_password"] != true {
		t.Fatalf("Unexpected user: %v", created)
	}

	admin.call(http.MethodPost, "/users", newUser, http.StatusConflict, nil)
	admin.call(http.MethodPost, "/users", map[string]interface{}{"preferred_username": "short", "password": "1234"}, http.StatusBadRequest, nil)
	admin.call(http.MethodPost, "/users", map[string]interface{}{"preferred_username": "x", "password": "long-password", "unknown": 1}, http.StatusBadRequest, nil)

	// the new user can log in
	resp, body := s.login(t, browser(t), s.url("/login"), "new", "new-password")
	expectStatus(t, resp, body, http.StatusFound)

	// update: an empty password keeps the current one
	admin.call(http.MethodPut, "/users/"+subject, map[string]interface{}{"preferred_username": "renamed", "name": "New User"}, http.StatusOK, nil)
	resp, body = s.login(t, browser(t), s.url("/login"), "renamed", "new-password")
	expectStatus(t, resp, body, http.StatusFound)

	admin.call(http.MethodPut, "/users/"+subject, map[string]interface{}{"preferred_username": "renamed", "password": "changed-password"}, http.StatusOK, nil)
	resp, body = s.login(t, browser(t), s.url("/login"), "renamed", "changed-password")
	expectStatus(t, resp, body, http.StatusFound)

	admin.call(http.MethodPut, "/users/"+subject, map[string]interface{}{"preferred_username": "other"}, http.StatusConflict, nil)

	// the administrator cannot lock themselves out
	admin.call(http.MethodPut, "/users/1", map[string]interface{}{"preferred_username": username, "groups": []string{}}, http.StatusBadRequest, nil)
	admin.call(http.MethodDelete, "/users/1", nil, http.StatusBadRequest, nil)

	// sessions
	var sessions []map[string]interface{}
	admin.call(http.MethodGet, "/users/"+subject+"/sessions", nil, http.StatusOK, &sessions)
	if len(sessions) != 3 {
		t.Fatalf("Expected 3 sessions: %v", sessions)
	}
	admin.call(http.MethodDelete, "/users/"+subject+"/sessions/"+sessions[0]["id"].(string), nil, http.StatusNoContent, nil)
	admin.call(http.MethodDelete, "/users/"+subject+"/sessions/unknown", nil, http.StatusNotFound, nil)
	admin.call(http.MethodDelete, "/users/"+subject+"/sessions", nil, http.StatusNoContent, nil)
	admin.call(http.MethodGet, "/users/"+subject+"/sessions", nil, http.StatusOK, &sessions)
	if len(sessions) != 0 {
		t.Fatalf("Expected no sessions: %v", sessions)
	}

	admin.call(http.MethodGet, "/users/1/sessions", nil, http.StatusOK, &sessions)
	if len(sessions) != 1 || sessions[0]["current"] != true {
		t.Fatalf("Expected the current session: %v", sessions)
	}

	// blocked users can be unblocked
	c := browser(t)
	for i := 0; i < 5; i++ {
		s.login(t, c, s.url("/login"), "renamed", "wrong")
	}
	var user map[string]interface{}
	admin.call(http.MethodGet, "/users/"+subject, nil, http.StatusOK, &user)
	if user["blocked"] != true {
		t.Fatalf("Expected a blocked user: %v", user)
	}
	admin.call(http.MethodPost, "/users/"+subject+"/unblock", nil, http.StatusNoContent, nil)
	resp, body = s.login(t, c, s.url("/login"), "renamed", "changed-password")
	expectStatus(t, resp, body, http.StatusFound)

	admin.call(http.MethodDelete, "/users/"+subject+"/mfa", nil, http.StatusNoContent, nil)
	admin.call(http.MethodDelete, "/users/"+subject, nil, http.StatusNoContent, nil)
	admin.call(http.MethodGet, "/users/"+subject, nil, http.StatusNotFound, nil)
	resp, body = s.login(t, browser(t), s.url("/login"), "renamed", "changed-password")
	if !strings.Contains(body, "Invalid login") {
		t.Errorf("Expected the deleted user not to log in: %d %s", resp.StatusCode, body)
	}
}

func TestAdminManagesClients(t *testing.T) {
	s, _ := newAdminServer(t)
	admin := s.loginAs(t, username)

	var clients []map[string]interface{}
	admin.call(http.MethodGet, "/clients", nil, http.StatusOK, &clients)
	if len(clients) != 3 {
		t.Fatalf("Expected the 3 clients of the configuration: %v", clients)
	}

	var created map[string]interface{}
	admin.call(http.MethodPost, "/clients", map[string]interface{}{
		"id": "web", "token_endpoint_auth_method": "client_secret_basic", "redirect_uris": []string{"https://web.test/callback"},
	}, http.StatusCreated, &created)
	secret, _ := created["secret"].(string)
	if secret == "" || created["has_secret"] != true {
		t.Fatalf("Expected a generated secret: %v", created)
	}

	introspect := func(id, secret string) int {
		resp, _ := postForm(t, http.DefaultClient, s.url("/connect/introspect"), url.Values{"token": {"x"}}, basicAuth(id, secret))
		return resp.StatusCode
	}
	if introspect("web", secret) != http.StatusOK {
		t.Fatal("Expected the generated secret to authenticate the client")
	}

	// the secret is not returned again
	var client map[string]interface{}
	admin.call(http.MethodGet, "/clients/web", nil, http.StatusOK, &client)
	if _, ok := client["secret"]; ok {
		t.Fatal("The secret must only be returned once")
	}

	var rotated map[string]interface{}
	admin.call(http.MethodPost, "/clients/web/secret", nil, http.StatusOK, &rotated)
	if introspect("web", secret) != http.StatusUnauthorized || introspect("web", rotated["secret"].(string)) != http.StatusOK {
		t.Fatal("Expected the secret to be rotated")
	}

	// changing to client_secret_jwt generates a plain secret
	var updated map[string]interface{}
	admin.call(http.MethodPut, "/clients/web", map[string]interface{}{
		"token_endpoint_auth_method": "client_secret_jwt", "redirect_uris": []string{"https://web.test/callback"},
	}, http.StatusOK, &updated)
	if len(updated["secret"].(string)) < 32 {
		t.Fatalf("Expected a new secret for client_secret_jwt: %v", updated)
	}

	// private_key_jwt with a PEM public key
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	publicKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	var backend map[string]interface{}
	admin.call(http.MethodPost, "/clients", map[string]interface{}{
		"id": "backend", "token_endpoint_auth_method": "private_key_jwt", "public_keys": []string{publicKey},
	}, http.StatusCreated, &backend)
	if backend["secret"] != nil || len(backend["public_keys"].([]interface{})) != 1 {
		t.Fatalf("Unexpected client: %v", backend)
	}

	for name, body := range map[string]map[string]interface{}{
		"invalid redirect uri":     {"id": "bad", "redirect_uris": []string{"/relative"}},
		"invalid public key":       {"id": "bad", "token_endpoint_auth_method": "private_key_jwt", "public_keys": []string{"not a key"}},
		"private key without keys": {"id": "bad", "token_endpoint_auth_method": "private_key_jwt"},
		"unknown method":           {"id": "bad", "token_endpoint_auth_method": "magic"},
		"without id":               {"token_endpoint_auth_method": "none"},
	} {
		resp, text := admin.do(http.MethodPost, "/clients", body, true)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d %s", name, resp.StatusCode, text)
		}
	}
	admin.call(http.MethodPost, "/clients", map[string]interface{}{"id": "web"}, http.StatusConflict, nil)

	// revoking the tokens of a client
	tk := s.exchangeCode(t, s.authorize(t, browser(t), authorizePath(clientID, nil)))
	admin.call(http.MethodDelete, "/clients/"+clientID+"/tokens", nil, http.StatusNoContent, nil)
	resp, body := s.refresh(http.DefaultClient, t, tk.RefreshToken)
	expectError(t, resp, body, http.StatusBadRequest, "invalid_grant")

	admin.call(http.MethodDelete, "/clients/web", nil, http.StatusNoContent, nil)
	admin.call(http.MethodGet, "/clients/web", nil, http.StatusNotFound, nil)
}

func TestAdminLogoutAll(t *testing.T) {
	s, _ := newAdminServer(t)
	admin := s.loginAs(t, username)
	tk := s.exchangeCode(t, s.authorize(t, browser(t), authorizePath(clientID, nil)))

	admin.call(http.MethodPost, "/maintenance/logout-all", nil, http.StatusNoContent, nil)

	resp, body := s.userinfo(t, tk.AccessToken)
	expectError(t, resp, body, http.StatusUnauthorized, "invalid_token")
	resp, body = admin.do(http.MethodGet, "/users", nil, false)
	expectStatus(t, resp, body, http.StatusUnauthorized)
}

// the changes made in the admin web are kept after a restart: the users and
// clients of the configuration are only added when they do not exist
func TestAdminChangesSurviveARestart(t *testing.T) {
	s, database := newAdminServer(t)
	admin := s.loginAs(t, username)
	admin.call(http.MethodPut, "/users/2", map[string]interface{}{"preferred_username": "other", "name": "Changed"}, http.StatusOK, nil)
	admin.call(http.MethodDelete, "/clients/"+otherClientID, nil, http.StatusNoContent, nil)

	restarted := newTestServer(t, false, withAdmin(database))
	admin = restarted.loginAs(t, username)
	var user map[string]interface{}
	admin.call(http.MethodGet, "/users/2", nil, http.StatusOK, &user)
	if user["name"] != "Changed" {
		t.Errorf("Expected the change to be kept: %v", user)
	}

	// the deleted client of the configuration is added again
	admin.call(http.MethodGet, "/clients/"+otherClientID, nil, http.StatusOK, nil)
}

func TestAdminRequiresClientsInSQLite(t *testing.T) {
	b := &api.Builder{Issuer: issuer, Audience: audience, AdminEnabled: true}
	if _, err := b.Build(); err == nil {
		t.Fatal("Expected an error without the clients in SQLite")
	}
}

func TestAdminSearchesUsers(t *testing.T) {
	s, _ := newAdminServer(t)
	admin := s.loginAs(t, username)
	for i := range 12 {
		admin.call(http.MethodPost, "/users", map[string]interface{}{
			"preferred_username": fmt.Sprintf("member%02d", i), "password": "12345678", "groups": []string{"team"},
		}, http.StatusCreated, nil)
	}
	admin.call(http.MethodPost, "/users/2/disable", map[string]string{}, http.StatusOK, nil)

	type page struct {
		Users []struct {
			PreferredUsername string `json:"preferred_username"`
		} `json:"users"`
		Total int `json:"total"`
	}
	search := func(query string) page {
		t.Helper()
		var p page
		admin.call(http.MethodGet, "/users?"+query, nil, http.StatusOK, &p)
		return p
	}

	if p := search(""); p.Total != 14 || len(p.Users) != 14 {
		t.Errorf("Expected all the users, got %d of %d", len(p.Users), p.Total)
	}

	// the pages keep the order of the store
	first, second := search("q=member&limit=5"), search("q=member&limit=5&offset=10")
	if first.Total != 12 || len(first.Users) != 5 || first.Users[0].PreferredUsername != "member00" {
		t.Errorf("Unexpected first page: %+v", first)
	}
	if second.Total != 12 || len(second.Users) != 2 || second.Users[1].PreferredUsername != "member11" {
		t.Errorf("Unexpected last page: %+v", second)
	}

	for query, expected := range map[string]string{
		"q=TEAM&limit=1":  "member00", // the groups too
		"status=disabled": "other",
		"status=admin":    username,
	} {
		if p := search(query); len(p.Users) != 1 || p.Users[0].PreferredUsername != expected {
			t.Errorf("%s: expected %s, got %+v", query, expected, p)
		}
	}
	if p := search("status=no_mfa"); p.Total != 14 {
		t.Errorf("Expected all the users without MFA, got %d", p.Total)
	}
	admin.call(http.MethodGet, "/users?status=unknown", nil, http.StatusBadRequest, nil)
	admin.call(http.MethodGet, "/users?limit=-1", nil, http.StatusBadRequest, nil)
}

func TestAdminOverview(t *testing.T) {
	s, _ := newAdminServer(t)
	admin := s.loginAs(t, username)
	s.expectLoginError(t, "other", "wrong", "")
	admin.call(http.MethodPost, "/users/2/lock", map[string]string{}, http.StatusOK, nil)

	var overview struct {
		Users struct {
			Total         int `json:"total"`
			Admins        int `json:"admins"`
			Locked        int `json:"locked"`
			NeverSignedIn int `json:"never_signed_in"`
		} `json:"users"`
		Clients   int            `json:"clients"`
		Groups    int            `json:"groups"`
		Activity  map[string]int `json:"activity"`
		Incidents []eventDTO     `json:"incidents"`
	}
	admin.call(http.MethodGet, "/overview", nil, http.StatusOK, &overview)
	if overview.Users.Total != 2 || overview.Users.Admins != 1 || overview.Users.Locked != 1 || overview.Users.NeverSignedIn != 1 {
		t.Errorf("Unexpected users: %+v", overview.Users)
	}
	if overview.Clients != 3 || overview.Groups != 1 || overview.Activity["failed_logins"] != 1 {
		t.Errorf("Unexpected overview: %+v", overview)
	}
	if len(overview.Incidents) != 1 || overview.Incidents[0].Username != "other" {
		t.Errorf("Expected the failed login as incident: %+v", overview.Incidents)
	}
}

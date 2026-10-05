package api_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/api"
)

// withPasswordGrant lets the confidential client use the password grant
func withPasswordGrant(b *api.Builder) {
	b.AllowPasswordGrant = true
	b.Clients[0].GrantTypes = []string{"authorization_code", "refresh_token", "password"}
}

func (s *testServer) passwordGrant(t *testing.T, user, pass string) (*http.Response, string) {
	t.Helper()
	return postForm(t, http.DefaultClient, s.url("/connect/token"), url.Values{
		"grant_type": {"password"}, "username": {user}, "password": {pass}, "scope": {"openid"},
	}, basicAuth(clientID, clientSecret))
}

// expectSignedOut checks that the browser has no session
func (s *testServer) expectSignedOut(t *testing.T, c *http.Client) {
	t.Helper()
	resp, _ := get(t, c, s.url("/profile"))
	expectLoginRedirect(t, resp)
}

func (s *testServer) expectLoginError(t *testing.T, user, pass, message string) {
	t.Helper()
	resp, body := s.login(t, browser(t), s.url("/login"), user, pass)
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, message) {
		t.Errorf("Expected %q in the login: %s", message, body)
	}
}

type userState struct {
	Disabled               bool    `json:"disabled"`
	DisabledReason         string  `json:"disabled_reason"`
	DisabledBy             string  `json:"disabled_by"`
	Locked                 bool    `json:"locked"`
	LockedUntil            *string `json:"locked_until"`
	PasswordChangeRequired bool    `json:"password_change_required"`
}

func TestAdminDisablesAUser(t *testing.T) {
	s, _ := newAdminServer(t, withPasswordGrant)
	admin := s.loginAs(t, username)
	other := s.loginAs(t, "other")
	a := newAuthenticator(t)
	s.registerPasskey(t, other.http, a, "phone")

	// an administrator cannot disable themselves
	admin.call(http.MethodPost, "/users/1/disable", map[string]string{}, http.StatusBadRequest, nil)

	var state userState
	admin.call(http.MethodPost, "/users/2/disable", map[string]string{"reason": "left the company"}, http.StatusOK, &state)
	if !state.Disabled || state.DisabledReason != "left the company" || state.DisabledBy != username {
		t.Errorf("Unexpected state: %+v", state)
	}

	// the sessions are closed, and the account cannot be used by any way
	s.expectSignedOut(t, other.http)
	s.expectLoginError(t, "other", password, "This account is disabled")
	s.expectLoginError(t, "other", "wrong", "Invalid login")
	resp, body := s.passkeyLogin(t, browser(t), a, "")
	expectStatus(t, resp, body, http.StatusForbidden)
	resp, body = s.passwordGrant(t, "other", password)
	expectError(t, resp, body, http.StatusBadRequest, "invalid_grant")

	admin.call(http.MethodPost, "/users/2/enable", map[string]string{}, http.StatusOK, &state)
	if state.Disabled {
		t.Errorf("Expected the account enabled: %+v", state)
	}
	resp, body = s.passwordGrant(t, "other", password)
	expectStatus(t, resp, body, http.StatusOK)
	s.loginAs(t, "other")
}

func TestAdminLocksAUser(t *testing.T) {
	s, _ := newAdminServer(t)
	admin := s.loginAs(t, username)
	other := s.loginAs(t, "other")

	admin.call(http.MethodPost, "/users/2/lock", map[string]string{"until": s.clock.Now().Add(-time.Hour).Format(time.RFC3339)}, http.StatusBadRequest, nil)

	var state userState
	until := s.clock.Now().Add(time.Hour).Format(time.RFC3339)
	admin.call(http.MethodPost, "/users/2/lock", map[string]string{"until": until, "reason": "holidays"}, http.StatusOK, &state)
	if !state.Locked || state.LockedUntil == nil {
		t.Fatalf("Unexpected state: %+v", state)
	}
	s.expectSignedOut(t, other.http)
	s.expectLoginError(t, "other", password, "This account is locked")

	// the lock ends by itself
	s.clock.Advance(2 * time.Hour)
	s.loginAs(t, "other")

	// until it is unlocked (the admin logs in again: the actions need a recent login)
	admin = s.loginAs(t, username)
	admin.call(http.MethodPost, "/users/2/lock", map[string]string{}, http.StatusOK, &state)
	s.clock.Advance(365 * 24 * time.Hour)
	s.expectLoginError(t, "other", password, "This account is locked")
	admin = s.loginAs(t, username)
	admin.call(http.MethodPost, "/users/2/unblock", map[string]string{}, http.StatusNoContent, nil)
	s.loginAs(t, "other")
}

var passwordFieldRegex = regexp.MustCompile(`"password":"([^"]+)"`)

func TestTemporaryPassword(t *testing.T) {
	s, _ := newAdminServer(t, withPasswordGrant)
	admin := s.loginAs(t, username)
	other := s.loginAs(t, "other")

	resp, body := admin.do(http.MethodPost, "/users/2/temporary-password", map[string]string{}, true)
	expectStatus(t, resp, body, http.StatusOK)
	temporary := passwordFieldRegex.FindStringSubmatch(body)[1]
	if !regexp.MustCompile(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$`).MatchString(temporary) {
		t.Errorf("Unexpected temporary password %q", temporary)
	}

	// the sessions are closed and the old password does not work
	s.expectSignedOut(t, other.http)
	s.expectLoginError(t, "other", password, "Invalid login")

	// the temporary password only works in the login page, to change it
	resp, body = s.passwordGrant(t, "other", temporary)
	expectError(t, resp, body, http.StatusBadRequest, "invalid_grant")

	c := browser(t)
	resp, body = s.login(t, c, s.url("/login?return_url="+url.QueryEscape(authorizePath(clientID, nil))), "other", temporary)
	expectStatus(t, resp, body, http.StatusFound)
	resp, _ = get(t, c, s.resolve(t, resp))
	expectRedirectTo(t, resp, "/profile/password?return_url=")
	changeURL := s.resolve(t, resp)
	resp, _ = get(t, c, s.url("/profile"))
	expectRedirectTo(t, resp, "/profile/password")

	resp, body = get(t, c, changeURL)
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, "Your password is temporary") {
		t.Errorf("Expected the temporary password message: %s", body)
	}

	// the new password must be different
	change := url.Values{"current_password": {temporary}, "new_password": {temporary}, "confirm_password": {temporary}, "__csrf": {csrfRegex.FindStringSubmatch(body)[1]}}
	resp, body = postForm(t, c, changeURL, change)
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, "must be different") {
		t.Errorf("Expected a same password error: %s", body)
	}

	change.Set("new_password", "my new password")
	change.Set("confirm_password", "my new password")
	change.Set("__csrf", csrfRegex.FindStringSubmatch(body)[1])
	resp, _ = postForm(t, c, changeURL, change)
	// the user continues to the application
	expectRedirectTo(t, resp, "/connect/authorize")
	code := s.authorize(t, c, strings.TrimPrefix(s.resolve(t, resp), s.URL))
	if code == "" {
		t.Error("Expected an authorization code")
	}

	resp, body = s.passwordGrant(t, "other", "my new password")
	expectStatus(t, resp, body, http.StatusOK)
}

func TestPasswordResetLink(t *testing.T) {
	s, _ := newAdminServer(t)
	admin := s.loginAs(t, username)
	other := s.loginAs(t, "other")

	var link struct {
		URL string `json:"url"`
	}
	admin.call(http.MethodPost, "/users/2/reset-link", map[string]string{}, http.StatusOK, &link)
	if !strings.HasPrefix(link.URL, issuer+"reset-password?token=") {
		t.Fatalf("Unexpected link %s", link.URL)
	}
	resetURL := s.url(strings.TrimPrefix(link.URL, strings.TrimSuffix(issuer, "/")))

	// creating the link does not change the password
	s.loginAs(t, "other")

	c := browser(t)
	resp, body := get(t, c, resetURL)
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, "<strong>other</strong>") {
		t.Errorf("Expected the username: %s", body)
	}

	form := url.Values{
		"token":        {regexp.MustCompile(`name="token" value="([^"]+)"`).FindStringSubmatch(body)[1]},
		"new_password": {"reset password"}, "confirm_password": {"another one"},
		"__csrf": {csrfRegex.FindStringSubmatch(body)[1]},
	}
	resp, body = postForm(t, c, s.url("/reset-password"), form)
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, "do not match") {
		t.Errorf("Expected a mismatch error: %s", body)
	}

	form.Set("confirm_password", "reset password")
	form.Set("__csrf", csrfRegex.FindStringSubmatch(body)[1])
	resp, _ = postForm(t, c, s.url("/reset-password"), form)
	expectRedirectTo(t, resp, "/login?reset=1")
	resp, body = get(t, c, s.resolve(t, resp))
	if !strings.Contains(body, "Your password has been changed") {
		t.Errorf("Expected the reset message: %s", body)
	}

	// the sessions are closed and the link is used once
	s.expectSignedOut(t, other.http)
	resp, body = get(t, c, resetURL)
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, "This link is not valid") {
		t.Errorf("Expected an invalid link: %s", body)
	}
	s.expectLoginError(t, "other", password, "Invalid login")
	resp, body = s.login(t, browser(t), s.url("/login"), "other", "reset password")
	expectStatus(t, resp, body, http.StatusFound)

	// a new link replaces the previous one, and they expire
	admin = s.loginAs(t, username)
	admin.call(http.MethodPost, "/users/2/reset-link", map[string]string{}, http.StatusOK, &link)
	first := link.URL
	admin.call(http.MethodPost, "/users/2/reset-link", map[string]string{}, http.StatusOK, &link)
	_, body = get(t, c, s.url(strings.TrimPrefix(first, strings.TrimSuffix(issuer, "/"))))
	if !strings.Contains(body, "This link is not valid") {
		t.Errorf("Expected the first link replaced: %s", body)
	}
	s.clock.Advance(25 * time.Hour)
	resp, body = get(t, c, s.url(strings.TrimPrefix(link.URL, strings.TrimSuffix(issuer, "/"))))
	if !strings.Contains(body, "This link is not valid") {
		t.Errorf("Expected an expired link: %s", body)
	}
}

func TestAdminSetsAPassword(t *testing.T) {
	s, _ := newAdminServer(t)
	admin := s.loginAs(t, username)

	admin.call(http.MethodPost, "/users/2/password", map[string]interface{}{"password": "short"}, http.StatusBadRequest, nil)

	var state userState
	admin.call(http.MethodPost, "/users/2/password", map[string]interface{}{"password": "chosen by admin", "require_change": false}, http.StatusOK, &state)
	if state.PasswordChangeRequired {
		t.Errorf("Expected no password change: %+v", state)
	}
	s.expectLoginError(t, "other", password, "Invalid login")
	c := browser(t)
	resp, body := s.login(t, c, s.url("/login"), "other", "chosen by admin")
	expectStatus(t, resp, body, http.StatusFound)
	resp, body = get(t, c, s.url("/profile"))
	expectStatus(t, resp, body, http.StatusOK)

	admin.call(http.MethodPost, "/users/2/password", map[string]interface{}{"password": "chosen again", "require_change": true}, http.StatusOK, &state)
	if !state.PasswordChangeRequired {
		t.Errorf("Expected a password change: %+v", state)
	}
}

func TestSensitiveAdminActionsNeedARecentLogin(t *testing.T) {
	s, _ := newAdminServer(t)
	admin := s.loginAs(t, username)
	s.clock.Advance(11 * time.Minute)

	for _, path := range []string{"/users/2/disable", "/users/2/lock", "/users/2/password", "/users/2/temporary-password", "/users/2/reset-link"} {
		resp, body := admin.do(http.MethodPost, path, map[string]string{"password": "12345678"}, true)
		expectStatus(t, resp, body, http.StatusForbidden)
		var answer struct {
			Reauthenticate bool `json:"reauthenticate"`
		}
		if err := json.Unmarshal([]byte(body), &answer); err != nil || !answer.Reauthenticate {
			t.Errorf("%s: expected a reauthentication, got %s", path, body)
		}
	}
	resp, body := admin.do(http.MethodDelete, "/users/2", nil, true)
	expectStatus(t, resp, body, http.StatusForbidden)

	// the actions that give the access back do not need it
	admin.call(http.MethodPost, "/users/2/enable", map[string]string{}, http.StatusOK, nil)
	admin.call(http.MethodPost, "/users/2/unblock", map[string]string{}, http.StatusNoContent, nil)
}

// the users of the configuration can be locked and disabled, but their
// passwords are in the configuration
func TestAdminWithTheUsersOfTheConfiguration(t *testing.T) {
	database := t.TempDir() + "/admin.sqlite3"
	s := newTestServer(t, false, func(b *api.Builder) {
		b.UseSQLite(database, api.All&^api.Users)
		b.AdminEnabled = true
		b.Users[0].Groups = []string{"admin"}
	})
	admin := s.loginAs(t, username)

	var info struct {
		UsersReadonly       bool `json:"users_readonly"`
		UsersListable       bool `json:"users_listable"`
		PasswordsManageable bool `json:"passwords_manageable"`
	}
	admin.call(http.MethodGet, "/info", nil, http.StatusOK, &info)
	if !info.UsersReadonly || !info.UsersListable || info.PasswordsManageable {
		t.Errorf("Unexpected info: %+v", info)
	}

	var users []struct{}
	admin.listUsers(&users)
	if len(users) != 2 {
		t.Errorf("Expected the users of the configuration, got %d", len(users))
	}

	admin.call(http.MethodPost, "/users/2/reset-link", map[string]string{}, http.StatusMethodNotAllowed, nil)
	admin.call(http.MethodPost, "/users/2/disable", map[string]string{}, http.StatusOK, nil)
	s.expectLoginError(t, "other", password, "This account is disabled")

	// the state is kept in SQLite
	restarted := newTestServer(t, false, func(b *api.Builder) { b.UseSQLite(database, api.All&^api.Users) })
	restarted.expectLoginError(t, "other", password, "This account is disabled")
}

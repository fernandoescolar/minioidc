package api_test

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

type eventDTO struct {
	ID       int64  `json:"id"`
	Type     string `json:"type"`
	Result   string `json:"result"`
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Actor    string `json:"actor"`
	ClientID string `json:"client_id"`
	IP       string `json:"ip"`
	Detail   string `json:"detail"`
}

type eventPage struct {
	Events []eventDTO `json:"events"`
	Next   int64      `json:"next"`
}

func (a *adminClient) events(query string) eventPage {
	a.t.Helper()
	var page eventPage
	a.call(http.MethodGet, "/events?"+query, nil, http.StatusOK, &page)
	return page
}

func findEvent(events []eventDTO, eventType, result string) (eventDTO, bool) {
	for _, e := range events {
		if e.Type == eventType && e.Result == result {
			return e, true
		}
	}

	return eventDTO{}, false
}

func TestActivityLog(t *testing.T) {
	s, _ := newAdminServer(t, withPasswordGrant)
	admin := s.loginAs(t, username)

	// the failed logins of a user: the last one blocks it
	for range 5 {
		s.expectLoginError(t, "other", "wrong", "")
	}
	resp, body := s.passwordGrant(t, "nobody", "wrong")
	expectError(t, resp, body, http.StatusBadRequest, "invalid_grant")
	admin.call(http.MethodPost, "/users/2/unblock", map[string]string{}, http.StatusNoContent, nil)
	other := s.loginAs(t, "other")
	admin.call(http.MethodPost, "/users/2/disable", map[string]string{"reason": "testing"}, http.StatusOK, nil)

	// the activity of the user has the failed logins (without subject) too
	page := admin.events("user=2")
	if e, ok := findEvent(page.Events, "login.password", "failure"); !ok || e.Username != "other" || e.UserID != "" || e.Detail != "invalid credentials" || e.IP == "" {
		t.Errorf("Expected the failed login: %+v", page.Events)
	}
	if _, ok := findEvent(page.Events, "login.lockout", "failure"); !ok {
		t.Errorf("Expected the lockout: %+v", page.Events)
	}
	if e, ok := findEvent(page.Events, "login.password", "success"); !ok || e.UserID != "2" {
		t.Errorf("Expected the login: %+v", page.Events)
	}
	if e, ok := findEvent(page.Events, "admin.state", "success"); !ok || e.Actor != username || e.Detail != "disabled: testing" {
		t.Errorf("Expected the admin action: %+v", page.Events)
	}
	if e, ok := findEvent(page.Events, "admin.state", "success"); ok && e.Detail == "unlocked" {
		t.Errorf("Expected the newest event first: %+v", page.Events)
	}
	s.expectSignedOut(t, other.http)

	// the filters
	for query, check := range map[string]func(eventDTO) bool{
		"type=login.&result=failure": func(e eventDTO) bool { return strings.HasPrefix(e.Type, "login.") && e.Result == "failure" },
		"type=admin.":                func(e eventDTO) bool { return strings.HasPrefix(e.Type, "admin.") },
		"q=nobody":                   func(e eventDTO) bool { return e.Username == "nobody" && e.ClientID == clientID },
	} {
		page := admin.events(query)
		if len(page.Events) == 0 {
			t.Errorf("%s: expected events", query)
		}
		for _, e := range page.Events {
			if !check(e) {
				t.Errorf("%s: unexpected event %+v", query, e)
			}
		}
	}
	future := s.clock.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if page := admin.events("since=" + future); len(page.Events) != 0 {
		t.Errorf("Expected no events in the future: %+v", page.Events)
	}
	admin.call(http.MethodGet, "/events?since=yesterday", nil, http.StatusBadRequest, nil)

	// the pages
	first := admin.events("limit=3")
	if len(first.Events) != 3 || first.Next != first.Events[2].ID {
		t.Fatalf("Unexpected first page: %+v", first)
	}
	second := admin.events("limit=3&before=" + strconv.FormatInt(first.Next, 10))
	if len(second.Events) == 0 || second.Events[0].ID >= first.Next {
		t.Errorf("Unexpected second page: %+v", second)
	}

	var summary map[string]int
	admin.call(http.MethodGet, "/events/summary", nil, http.StatusOK, &summary)
	if summary["failed_logins"] < 6 || summary["lockouts"] != 1 || summary["logins"] < 2 || summary["admin_actions"] != 2 {
		t.Errorf("Unexpected summary: %+v", summary)
	}

	// the last login of the users
	var users []struct {
		Subject     string     `json:"subject"`
		LastLoginAt *time.Time `json:"last_login_at"`
	}
	admin.listUsers(&users)
	for _, u := range users {
		if u.LastLoginAt == nil {
			t.Errorf("Expected the last login of %s", u.Subject)
		}
	}
}

func TestActivityExport(t *testing.T) {
	s, _ := newAdminServer(t)
	admin := s.loginAs(t, username)
	// a spreadsheet must not run a username as a formula
	s.expectLoginError(t, "=HYPERLINK(\"http://evil.test\")", "wrong", "")

	resp, body := admin.do(http.MethodGet, "/events.csv?type=login.", nil, false)
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") {
		t.Errorf("Unexpected content type %s", resp.Header.Get("Content-Type"))
	}

	records, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil || len(records) < 3 || records[0][0] != "time" {
		t.Fatalf("Unexpected CSV %v: %s", err, body)
	}
	if !strings.Contains(body, `'=HYPERLINK`) {
		t.Errorf("Expected the formula escaped: %s", body)
	}
}

func TestActivityRetention(t *testing.T) {
	s, _ := newAdminServer(t)
	admin := s.loginAs(t, username)
	s.expectLoginError(t, "other", "wrong", "")

	s.clock.Advance(91 * 24 * time.Hour)
	s.minioidc.CleanExpired()

	admin = s.loginAs(t, username)
	for _, e := range admin.events("").Events {
		if e.Username == "other" {
			t.Errorf("Expected the old events removed: %+v", e)
		}
	}
}

func TestActivityOfTheUsers(t *testing.T) {
	s, _ := newAdminServer(t)
	c := s.loginAs(t, "other").http
	a := newAuthenticator(t)
	s.registerPasskey(t, c, a, "phone")
	resp, body := s.passkeyLogin(t, browser(t), a, "")
	expectStatus(t, resp, body, http.StatusOK)

	admin := s.loginAs(t, username)
	events := admin.events("user=2").Events
	for _, expected := range []string{"account.passkey_add", "login.passkey"} {
		if _, ok := findEvent(events, expected, "success"); !ok {
			t.Errorf("Expected %s: %+v", expected, events)
		}
	}
}

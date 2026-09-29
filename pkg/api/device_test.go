package api_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"testing"

	"github.com/fernandoescolar/minioidc/pkg/api"
)

var deviceCodeRegex = regexp.MustCompile(`name="user_code" value="([^"]+)"`)

// The device codes are grants: with the grants in SQLite, a device code
// created in an instance is approved and exchanged in another one
func TestDeviceCodesAreSharedBetweenInstances(t *testing.T) {
	database := t.TempDir() + "/devices.sqlite3"
	options := func(b *api.Builder) {
		b.UseSQLite(database, api.Grants|api.Sessions)
		b.Clients = append(b.Clients, api.Client{ID: "tv", GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"}})
	}
	first := newTestServer(t, false, options)
	second := newTestServer(t, false, options)

	resp, body := postForm(t, http.DefaultClient, first.url("/connect/deviceauthorization"), url.Values{"client_id": {"tv"}, "scope": {"openid"}})
	expectStatus(t, resp, body, http.StatusOK)
	var device struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	if err := json.Unmarshal([]byte(body), &device); err != nil {
		t.Fatal(err)
	}

	// the user approves it in the second instance
	c := browser(t)
	loginResp, loginBody := second.login(t, c, second.url("/login"), username, password)
	expectStatus(t, loginResp, loginBody, http.StatusFound)

	resp, body = get(t, c, second.url("/connect/device?user_code="+url.QueryEscape(device.UserCode)))
	expectStatus(t, resp, body, http.StatusOK)
	if deviceCodeRegex.FindStringSubmatch(body) == nil {
		t.Fatalf("Expected the device confirmation page: %s", body)
	}

	resp, body = postForm(t, c, second.url("/connect/device"), url.Values{
		"user_code": {device.UserCode}, "action": {"approve"}, "__csrf": {csrfRegex.FindStringSubmatch(body)[1]},
	})
	expectStatus(t, resp, body, http.StatusOK)

	// the device polls the first instance
	poll := url.Values{"client_id": {"tv"}, "grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {device.DeviceCode}}
	resp, body = postForm(t, http.DefaultClient, first.url("/connect/token"), poll)
	expectStatus(t, resp, body, http.StatusOK)

	resp, body = postForm(t, http.DefaultClient, second.url("/connect/token"), poll)
	expectError(t, resp, body, http.StatusBadRequest, "invalid_grant")
}

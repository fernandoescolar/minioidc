package api_test

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fernandoescolar/minioidc/pkg/api"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
)

const setupCode = "TEST-SETUP-CODE-1234"

// withoutUsers is a new server: the users in SQLite, and none of them
func withoutUsers(database string) func(*api.Builder) {
	return func(b *api.Builder) {
		b.UseSQLite(database, api.All)
		b.AdminEnabled = true
		b.Users = nil
		b.SetupCode = setupCode
	}
}

func newSetupServer(t *testing.T, requireMFA bool) *testServer {
	t.Helper()
	return newTestServer(t, requireMFA, withoutUsers(t.TempDir()+"/setup.sqlite3"))
}

func expectRedirectTo(t *testing.T, resp *http.Response, path string) {
	t.Helper()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("Expected a redirect to %s, got %d", path, resp.StatusCode)
	}
	if location := resp.Header.Get("Location"); !strings.HasPrefix(location, path) {
		t.Fatalf("Expected a redirect to %s, got %s", path, location)
	}
}

// postSetup submits the setup form
func (s *testServer) postSetup(t *testing.T, c *http.Client, form url.Values) (*http.Response, string) {
	t.Helper()
	resp, body := get(t, c, s.url("/setup"))
	expectStatus(t, resp, body, http.StatusOK)
	form.Set("__csrf", csrfRegex.FindStringSubmatch(body)[1])
	return postForm(t, c, s.url("/setup"), form)
}

func setupForm(code string) url.Values {
	return url.Values{
		"code": {code}, "username": {"root"}, "name": {"The Admin"}, "email": {"root@mail.test"},
		"password": {"a strong password"}, "confirm_password": {"a strong password"},
	}
}

func TestSetupCreatesTheFirstAdministrator(t *testing.T) {
	s := newSetupServer(t, false)
	c := browser(t)

	// while there are no users, the login (where the home goes) sends to the setup
	resp, _ := get(t, c, s.url("/"))
	expectRedirectTo(t, resp, "/login")
	resp, _ = get(t, c, s.url("/login"))
	expectRedirectTo(t, resp, "/setup")

	// the code of the link is not asked again
	resp, body := get(t, c, s.url("/setup?code="+url.QueryEscape(setupCode)))
	expectStatus(t, resp, body, http.StatusOK)
	if strings.Contains(body, `id="code"`) || !strings.Contains(body, `name="code_from_link"`) {
		t.Errorf("Expected the code of the link in a hidden field: %s", body)
	}

	// the setup code is required
	resp, body = s.postSetup(t, c, setupForm("WRONG-CODE-0000-0000"))
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, "setup code is not valid") {
		t.Errorf("Expected an invalid code error: %s", body)
	}

	// and the passwords must match
	form := setupForm(setupCode)
	form.Set("confirm_password", "another password")
	resp, body = s.postSetup(t, c, form)
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, "passwords do not match") || !strings.Contains(body, `value="root"`) {
		t.Errorf("Expected a password mismatch error keeping the values: %s", body)
	}

	// the case, the spaces and the dashes of the code do not matter
	resp, body = s.postSetup(t, c, setupForm(" test setup code1234 "))
	expectRedirectTo(t, resp, "/welcome")

	// the administrator is signed in
	resp, body = get(t, c, s.url("/welcome"))
	expectStatus(t, resp, body, http.StatusOK)
	for _, expected := range []string{"is ready", "/admin/#/clients", "/.well-known/openid-configuration", "/profile/mfa"} {
		if !strings.Contains(body, expected) {
			t.Errorf("Expected %q in the welcome page: %s", expected, body)
		}
	}

	admin := &adminClient{t: t, s: s, http: c}
	var info struct {
		Me struct {
			PreferredUsername string `json:"preferred_username"`
			Name              string `json:"name"`
		} `json:"me"`
	}
	admin.call(http.MethodGet, "/info", nil, http.StatusOK, &info)
	if info.Me.PreferredUsername != "root" || info.Me.Name != "The Admin" {
		t.Errorf("Unexpected administrator: %+v", info.Me)
	}

	// the setup is closed: the pages are the usual ones
	resp, _ = get(t, c, s.url("/setup"))
	expectRedirectTo(t, resp, "/")
	anonymous := browser(t)
	resp, _ = postForm(t, anonymous, s.url("/setup"), setupForm(setupCode))
	expectRedirectTo(t, resp, "/")
	resp, body = get(t, anonymous, s.url("/login"))
	expectStatus(t, resp, body, http.StatusOK)

	var users []struct{}
	admin.listUsers(&users)
	if len(users) != 1 {
		t.Errorf("Expected only the administrator, got %d users", len(users))
	}

	// and the administrator can sign in again
	resp, body = s.login(t, browser(t), s.url("/login"), "root", "a strong password")
	expectStatus(t, resp, body, http.StatusFound)
}

func TestSetupWithRequiredMFA(t *testing.T) {
	s := newSetupServer(t, true)
	c := browser(t)

	resp, _ := s.postSetup(t, c, setupForm(setupCode))
	expectRedirectTo(t, resp, "/welcome")

	// the administrator adds an authenticator app before the welcome page
	resp, _ = get(t, c, s.url("/welcome"))
	expectRedirectTo(t, resp, "/mfa/create")
}

func TestSetupIsOnlyForNewServers(t *testing.T) {
	for name, server := range map[string]func(t *testing.T) *testServer{
		// there are users
		"with users": func(t *testing.T) *testServer { s, _ := newAdminServer(t); return s },
		// the users are not in SQLite: they cannot be created
		"without SQLite": func(t *testing.T) *testServer {
			return newTestServer(t, false, func(b *api.Builder) { b.Users = nil })
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := server(t)
			c := browser(t)

			resp, _ := get(t, c, s.url("/setup"))
			expectRedirectTo(t, resp, "/")
			resp, body := get(t, c, s.url("/login"))
			expectStatus(t, resp, body, http.StatusOK)
		})
	}
}

func TestShortSetupCodesAreRejected(t *testing.T) {
	builder := &api.Builder{Issuer: issuer, Audience: audience, SetupCode: "short"}
	if _, err := builder.Build(); err == nil || !strings.Contains(err.Error(), "setup code") {
		t.Errorf("Expected a setup code error, got %v", err)
	}
}

func TestDefaultBuilderKeepsTheKeys(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	first, err := api.NewDefaultBuilder(dir, issuer)
	if err != nil {
		t.Fatal(err)
	}

	if first.Issuer != issuer || !first.AdminEnabled || !first.UseCSP || first.UseSecureCookie || len(first.MasterKey) < cryptography.MinMasterKeyLength {
		t.Errorf("Unexpected default configuration: %+v", first)
	}
	if secure, _ := api.NewDefaultBuilder(dir, "https://login.example.com/"); !secure.UseSecureCookie || !secure.UseHSTS {
		t.Error("Expected secure cookies and HSTS with an https issuer")
	}

	for _, file := range []string{"masterkey", "private.pem"} {
		info, err := os.Stat(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("Expected %s only readable by the owner, got %v", file, info.Mode().Perm())
		}
	}
	if _, err := cryptography.LoadPrivateKey(first.PrivateRSAKeyFilepath); err != nil {
		t.Errorf("Expected a valid signing key: %v", err)
	}

	// the next start uses the same keys
	second, err := api.NewDefaultBuilder(dir, issuer)
	if err != nil {
		t.Fatal(err)
	}
	if second.MasterKey != first.MasterKey || second.PrivateRSAKeyFilepath != first.PrivateRSAKeyFilepath {
		t.Error("Expected the same keys after a restart")
	}
}

package api_test

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/api"
)

const settingsFile = `# my configuration
name: minioidc
require_mfa: ${REQUIRE_MFA}
ttl:
  access: 20 # minutes
`

type settingsDTO struct {
	Mode     string `json:"mode"`
	Editable bool   `json:"editable"`
	Version  string `json:"version"`
	Settings []struct {
		Key     string `json:"key"`
		Value   string `json:"value"`
		Running string `json:"running"`
		FromEnv bool   `json:"from_env"`
		Pending bool   `json:"pending"`
	} `json:"settings"`
	Server []struct {
		Label string `json:"label"`
		Value string `json:"value"`
	} `json:"server"`
}

func (s settingsDTO) get(t *testing.T, key string) (value, running string, fromEnv, pending bool) {
	t.Helper()
	for _, setting := range s.Settings {
		if setting.Key == key {
			return setting.Value, setting.Running, setting.FromEnv, setting.Pending
		}
	}

	t.Fatalf("setting %s not found", key)
	return "", "", false, false
}

// withConfigFile is a server loaded from a configuration file (its content
// is not used by the builder, only by the settings of the admin web)
func withConfigFile(t *testing.T) (func(*api.Builder), string) {
	path := t.TempDir() + "/config.yml"
	if err := os.WriteFile(path, []byte(settingsFile), 0o600); err != nil {
		t.Fatal(err)
	}

	return func(b *api.Builder) { b.ConfigFilepath = path }, path
}

func TestAdminEditsTheSettings(t *testing.T) {
	option, path := withConfigFile(t)
	s, _ := newAdminServer(t, option)
	admin := s.loginAs(t, username)

	var dto settingsDTO
	admin.call(http.MethodGet, "/settings", nil, http.StatusOK, &dto)
	if dto.Mode != "file" || !dto.Editable || dto.Version == "" {
		t.Fatalf("Unexpected settings: %+v", dto)
	}
	if value, running, _, pending := dto.get(t, "ttl.access"); value != "20" || running != "20" || pending {
		t.Errorf("Unexpected ttl.access: %s %s %v", value, running, pending)
	}
	if _, _, fromEnv, pending := dto.get(t, "require_mfa"); !fromEnv || pending {
		t.Error("Expected require_mfa from the environment")
	}

	// the values are validated, and the environment variables are kept
	// (the test issuer is http: HSTS and secure cookies would lock everybody out)
	for _, values := range []map[string]string{
		{"ttl.access": "0"}, {"issuer": "https://evil.test/"}, {"require_mfa": "true"},
		{"middlewares.hsts": "true"}, {"middlewares.secure_cookies": "true"},
	} {
		resp, body := admin.do(http.MethodPut, "/settings", map[string]interface{}{"version": dto.Version, "values": values}, true)
		expectStatus(t, resp, body, http.StatusBadRequest)
	}

	admin.call(http.MethodPut, "/settings", map[string]interface{}{
		"version": dto.Version, "values": map[string]string{"name": "Family SSO", "ttl.access": "15", "passkeys.enabled": "false"},
	}, http.StatusOK, &dto)

	// the changes apply after a restart
	if value, running, _, pending := dto.get(t, "name"); value != "Family SSO" || running != "minioidc" || !pending {
		t.Errorf("Expected a pending name, got %s %s %v", value, running, pending)
	}
	content, _ := os.ReadFile(path)
	for _, expected := range []string{"# my configuration", "name: Family SSO", "require_mfa: ${REQUIRE_MFA}", "access: 15 # minutes", "enabled: false"} {
		if !strings.Contains(string(content), expected) {
			t.Errorf("Expected %q in the file:\n%s", expected, content)
		}
	}

	// the old version is a conflict (someone else changed the file)
	resp, body := admin.do(http.MethodPut, "/settings", map[string]interface{}{"version": "old", "values": map[string]string{"name": "x"}}, true)
	expectStatus(t, resp, body, http.StatusConflict)

	var events eventPage
	admin.call(http.MethodGet, "/events?type=admin.settings", nil, http.StatusOK, &events)
	if len(events.Events) != 1 || events.Events[0].Detail != "name=Family SSO, passkeys.enabled=false, ttl.access=15" {
		t.Errorf("Expected the change in the activity log: %+v", events.Events)
	}

	// the settings need a recent login
	s.clock.Advance(11 * time.Minute)
	resp, body = admin.do(http.MethodPut, "/settings", map[string]interface{}{"version": dto.Version, "values": map[string]string{"name": "x"}}, true)
	expectStatus(t, resp, body, http.StatusForbidden)
}

func TestReadOnlySettingsFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write any file")
	}

	option, path := withConfigFile(t)
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	s, _ := newAdminServer(t, option)
	admin := s.loginAs(t, username)

	var dto settingsDTO
	admin.call(http.MethodGet, "/settings", nil, http.StatusOK, &dto)
	if dto.Editable {
		t.Error("Expected a read only file")
	}
	admin.call(http.MethodPut, "/settings", map[string]interface{}{"version": dto.Version, "values": map[string]string{"name": "x"}}, http.StatusMethodNotAllowed, nil)
}

// without a configuration file, the settings are read only, and the admin
// web generates a file with them
func TestSettingsWithoutAConfigurationFile(t *testing.T) {
	s, _ := newAdminServer(t)
	admin := s.loginAs(t, username)

	var dto settingsDTO
	admin.call(http.MethodGet, "/settings", nil, http.StatusOK, &dto)
	if dto.Mode != "default" || dto.Editable || len(dto.Server) == 0 || dto.Server[0].Value != issuer {
		t.Errorf("Unexpected settings: %+v", dto)
	}

	resp, body := admin.do(http.MethodGet, "/settings/config.yml", nil, false)
	expectStatus(t, resp, body, http.StatusOK)

	// the generated file can be loaded
	path := t.TempDir() + "/generated.yml"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MINIOIDC_MASTERKEY", "0123456789abcdefghijklmnopqrstuvwxyz")
	builder, err := api.NewYamlBuilder(path)
	if err != nil {
		t.Fatalf("Expected a valid file: %v\n%s", err, body)
	}
	if builder.Issuer != issuer || !builder.AdminEnabled || builder.Name != "minioidc" || builder.AccessTTL != 20*time.Minute ||
		builder.MasterKey != "0123456789abcdefghijklmnopqrstuvwxyz" {
		t.Errorf("Unexpected builder: %+v\n%s", builder, body)
	}
}

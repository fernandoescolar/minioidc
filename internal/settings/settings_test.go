package settings

import (
	"errors"
	"os"
	"strings"
	"testing"
)

const sample = `# the name of my server
name: Home SSO
masterkey: ${MINIOIDC_MASTERKEY} # from the environment
issuer: https://sso.example.com/
require_mfa: ${REQUIRE_MFA}
ttl:
  access: 30 # minutes
  refresh: 1440
clients:
  - id: myclient
    redirect_uris:
      - https://app.example.com/callback
`

func writeSample(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + "/config.yml"
	if err := os.WriteFile(path, []byte(sample), 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

func set(t *testing.T, f *File, key, value string) error {
	t.Helper()
	d, ok := Find(key)
	if !ok {
		t.Fatalf("unknown setting %s", key)
	}
	normalized, err := d.Validate(value)
	if err != nil {
		t.Fatal(err)
	}
	return f.Set(d, normalized)
}

func TestEditTheConfigurationFile(t *testing.T) {
	path := writeSample(t)
	f, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}

	if value, present, fromEnv := f.Get("ttl.access"); value != "30" || !present || fromEnv {
		t.Errorf("Unexpected ttl.access: %q %v %v", value, present, fromEnv)
	}
	if _, present, fromEnv := f.Get("require_mfa"); !present || !fromEnv {
		t.Error("Expected require_mfa from an environment variable")
	}
	if _, present, _ := f.Get("passkeys.enabled"); present {
		t.Error("Expected passkeys.enabled not present")
	}

	for key, value := range map[string]string{"name": "Family SSO", "ttl.access": "15", "passkeys.enabled": "false", "middlewares.hsts": "TRUE"} {
		if err := set(t, f, key, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := set(t, f, "require_mfa", "true"); !errors.Is(err, ErrFromEnv) {
		t.Errorf("Expected the environment variable kept, got %v", err)
	}

	if err := f.Save(); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	for _, expected := range []string{
		"# the name of my server", "name: Family SSO", "${MINIOIDC_MASTERKEY}", "# from the environment",
		"require_mfa: ${REQUIRE_MFA}", "access: 15 # minutes", "refresh: 1440", "passkeys:\n  enabled: false",
		"hsts: true", "https://app.example.com/callback",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("Expected %q in the file:\n%s", expected, content)
		}
	}

	if backup, err := os.ReadFile(path + ".bak"); err != nil || string(backup) != sample {
		t.Errorf("Expected the previous content in the backup: %v", err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o640 {
		t.Errorf("Expected the permissions kept, got %v", info.Mode().Perm())
	}

	// the file is read again with the new values
	again, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if value, _, _ := again.Get("passkeys.enabled"); value != "false" {
		t.Errorf("Expected the new section, got %q", value)
	}
}

func TestConflicts(t *testing.T) {
	path := writeSample(t)
	f, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}

	// someone edits the file meanwhile
	if err := os.WriteFile(path, []byte(sample+"# changed\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := set(t, f, "name", "Other"); err != nil {
		t.Fatal(err)
	}
	if err := f.Save(); !errors.Is(err, ErrConflict) {
		t.Errorf("Expected a conflict, got %v", err)
	}
	if data, _ := os.ReadFile(path); !strings.Contains(string(data), "# changed") {
		t.Error("Expected the file untouched")
	}
}

func TestValidation(t *testing.T) {
	for key, value := range map[string]string{
		"ttl.access": "0", "ttl.code": "61", "events.retention_days": "ten", "require_mfa": "maybe",
		"name": "", "passkeys.enabled": "2",
	} {
		d, _ := Find(key)
		if _, err := d.Validate(value); err == nil {
			t.Errorf("%s=%q: expected an error", key, value)
		}
	}

	d, _ := Find("name")
	if _, err := d.Validate("${MINIOIDC_MASTERKEY}"); err == nil {
		t.Error("Expected an error: a value cannot read the environment")
	}
}

func TestReadOnlyFile(t *testing.T) {
	path := writeSample(t)
	if err := Writable(path); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(path, 0o440); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 && Writable(path) == nil {
		t.Error("Expected a read only file")
	}
}

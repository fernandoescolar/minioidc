// Package settings edits the settings of the configuration file from the
// admin web. It changes the YAML document (not the expanded values), so the
// comments, the order and the ${VARIABLES} of the file are kept. The changes
// apply when the server restarts.
package settings

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
	"gopkg.in/yaml.v3"
)

// Kind is the type of the value of a setting
type Kind string

const (
	KindBool   Kind = "bool"
	KindInt    Kind = "int"
	KindString Kind = "string"
)

// Definition is a setting that can be edited
type Definition struct {
	// Key is the path in the YAML file (e.g. "ttl.access")
	Key         string
	Group       string
	Label       string
	Description string
	Kind        Kind
	// Min and Max are the limits of the integers
	Min, Max int
	// Default is the value when the file does not have it
	Default string
	// Running is the value that the server is using
	Running func(*domain.Config) string
}

var (
	ErrConflict = errors.New("the configuration file has changed since it was read: reload the page")
	ErrFromEnv  = errors.New("the value comes from an environment variable")
)

func boolValue(v bool) string { return strconv.FormatBool(v) }

func minutes(d time.Duration) string { return strconv.Itoa(int(d / time.Minute)) }

// Definitions are the editable settings. The rest (issuer, keys, databases,
// LDAP…) can break the clients or lock the administrators out: they are
// changed in the file.
var Definitions = []Definition{
	{Key: "name", Group: "General", Label: "Name", Description: "The name of the server in the pages and the authenticator apps.", Kind: KindString, Min: 1, Max: 64, Default: "minioidc",
		Running: func(c *domain.Config) string { return c.Name }},
	{Key: "require_mfa", Group: "Security", Label: "Require MFA", Description: "All the users must use an authenticator app or a passkey.", Kind: KindBool, Default: "false",
		Running: func(c *domain.Config) string { return boolValue(c.RequireMFA) }},
	{Key: "passkeys.enabled", Group: "Security", Label: "Passkeys", Description: "The users can sign in with passkeys.", Kind: KindBool, Default: "true",
		Running: func(c *domain.Config) string { return boolValue(c.PasskeysEnabled) }},
	{Key: "grants.implicit", Group: "Security", Label: "Implicit and hybrid flows", Description: "Discouraged (RFC 9700): the tokens go through the browser. The clients also need the grant type.", Kind: KindBool, Default: "false",
		Running: func(c *domain.Config) string { return boolValue(c.AllowImplicitFlow) }},
	{Key: "grants.password", Group: "Security", Label: "Password grant", Description: "Discouraged (RFC 9700): the client sees the password. The clients also need the grant type.", Kind: KindBool, Default: "false",
		Running: func(c *domain.Config) string { return boolValue(c.AllowPasswordGrant) }},
	{Key: "reuse_refresh_tokens", Group: "Security", Label: "Reuse refresh tokens", Description: "A refresh token can be used more than once (it is not rotated).", Kind: KindBool, Default: "false",
		Running: func(c *domain.Config) string { return boolValue(c.ReuseRefreshTokens) }},
	{Key: "ttl.access", Group: "Sessions and tokens", Label: "Access tokens (minutes)", Description: "The lifetime of the access and ID tokens.", Kind: KindInt, Min: 1, Max: 1440, Default: "20",
		Running: func(c *domain.Config) string { return minutes(c.AccessTTL) }},
	{Key: "ttl.refresh", Group: "Sessions and tokens", Label: "Refresh tokens (minutes)", Kind: KindInt, Min: 1, Max: 5256000, Default: "129600",
		Running: func(c *domain.Config) string { return minutes(c.RefreshTTL) }},
	{Key: "ttl.session", Group: "Sessions and tokens", Label: "Sessions (minutes)", Description: "The sessions are extended while they are used.", Kind: KindInt, Min: 1, Max: 5256000, Default: "129600",
		Running: func(c *domain.Config) string { return minutes(c.SessionTTL) }},
	{Key: "ttl.code", Group: "Sessions and tokens", Label: "Authorization codes (minutes)", Kind: KindInt, Min: 1, Max: 60, Default: "5",
		Running: func(c *domain.Config) string { return minutes(c.CodeTTL) }},
	{Key: "ttl.csrf", Group: "Sessions and tokens", Label: "Forms (minutes)", Description: "The time to submit a form before it expires.", Kind: KindInt, Min: 1, Max: 1440, Default: "5",
		Running: func(c *domain.Config) string { return minutes(c.CSRFTTL) }},
	{Key: "events.retention_days", Group: "Activity", Label: "Retention (days)", Description: "How long the activity log is kept.", Kind: KindInt, Min: 1, Max: 3650, Default: "90",
		Running: func(c *domain.Config) string { return strconv.Itoa(int(c.EventRetention / (24 * time.Hour))) }},
	{Key: "middlewares.secure_cookies", Group: "HTTP", Label: "Secure cookies", Description: "The cookies are only sent with https. It needs an https issuer.", Kind: KindBool, Default: "false",
		Running: func(c *domain.Config) string { return boolValue(c.UseSecureCookie) }},
	{Key: "middlewares.hsts", Group: "HTTP", Label: "HSTS", Description: "The http requests are redirected to https, and the browsers only use https. It needs an https issuer.", Kind: KindBool, Default: "false",
		Running: func(c *domain.Config) string { return boolValue(c.UseHSTS) }},
	{Key: "middlewares.csp", Group: "HTTP", Label: "Content Security Policy", Kind: KindBool, Default: "false",
		Running: func(c *domain.Config) string { return boolValue(c.UseCSP) }},
	{Key: "middlewares.forward_headers", Group: "HTTP", Label: "Proxy headers", Description: "Trust the X-Forwarded-* headers: only behind a reverse proxy.", Kind: KindBool, Default: "false",
		Running: func(c *domain.Config) string { return boolValue(c.UseForwardedHeaders) }},
	{Key: "middlewares.log_requests", Group: "HTTP", Label: "Log the requests", Kind: KindBool, Default: "false",
		Running: func(c *domain.Config) string { return boolValue(c.LogRequests) }},
}

// httpsOnly are the settings that lock everybody out with an http issuer: the
// requests are redirected to https, or the browsers do not send the cookies
var httpsOnly = map[string]bool{"middlewares.hsts": true, "middlewares.secure_cookies": true}

// CheckIssuer returns an error if the value of the setting cannot be used
// with the issuer
func (d Definition) CheckIssuer(value, issuer string) error {
	if httpsOnly[d.Key] && value == "true" && !strings.HasPrefix(issuer, "https://") {
		return fmt.Errorf("%s needs an https issuer: with %s nobody could sign in", d.Label, issuer)
	}

	return nil
}

// Find returns the definition of a key
func Find(key string) (Definition, bool) {
	for _, d := range Definitions {
		if d.Key == key {
			return d, true
		}
	}

	return Definition{}, false
}

// Validate normalizes the value of a setting ("true", "20"…)
func (d Definition) Validate(value string) (string, error) {
	value = strings.TrimSpace(value)
	switch d.Kind {
	case KindBool:
		b, err := strconv.ParseBool(value)
		if err != nil {
			return "", fmt.Errorf("%s must be true or false", d.Label)
		}
		return strconv.FormatBool(b), nil
	case KindInt:
		n, err := strconv.Atoi(value)
		if err != nil || n < d.Min || n > d.Max {
			return "", fmt.Errorf("%s must be a number between %d and %d", d.Label, d.Min, d.Max)
		}
		return strconv.Itoa(n), nil
	default:
		if n := len([]rune(value)); n < d.Min || n > d.Max || strings.ContainsAny(value, "\n\r$") {
			return "", fmt.Errorf("%s must have between %d and %d characters, without $", d.Label, d.Min, d.Max)
		}
		return value, nil
	}
}

// File is a configuration file
type File struct {
	Path string
	// Version identifies the content: a write fails if the file has changed
	Version string
	root    yaml.Node
	mode    os.FileMode
}

// Read parses the configuration file
func Read(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	f := &File{Path: path, Version: version(data), mode: info.Mode().Perm()}
	if err := yaml.Unmarshal(data, &f.root); err != nil {
		return nil, fmt.Errorf("the configuration file is not valid YAML: %w", err)
	}
	if f.root.Kind == 0 {
		// an empty file
		f.root = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	if f.root.Kind != yaml.DocumentNode || len(f.root.Content) != 1 || f.root.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("the configuration file must be a YAML mapping")
	}

	return f, nil
}

func version(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}

// Get returns the value of a key in the file: present is false if it is not
// there, and fromEnv is true if it is a ${VARIABLE}
func (f *File) Get(key string) (value string, present, fromEnv bool) {
	node := f.root.Content[0]
	for _, part := range strings.Split(key, ".") {
		node = child(node, part)
		if node == nil {
			return "", false, false
		}
	}

	if node.Kind != yaml.ScalarNode {
		return "", false, false
	}

	return node.Value, true, strings.Contains(node.Value, "$")
}

// Set changes (or adds) the value of a key
func (f *File) Set(d Definition, value string) error {
	if _, present, fromEnv := f.Get(d.Key); present && fromEnv {
		return fmt.Errorf("%s: %w", d.Label, ErrFromEnv)
	}

	node := f.root.Content[0]
	parts := strings.Split(d.Key, ".")
	for _, part := range parts[:len(parts)-1] {
		next := child(node, part)
		if next == nil {
			next = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: part}, next)
		}
		if next.Kind != yaml.MappingNode {
			return fmt.Errorf("%s is not a section in the configuration file", part)
		}
		node = next
	}

	last := parts[len(parts)-1]
	target := child(node, last)
	if target == nil {
		target = &yaml.Node{Kind: yaml.ScalarNode}
		node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: last}, target)
	}

	target.Kind, target.Value, target.Style = yaml.ScalarNode, value, 0
	switch d.Kind {
	case KindBool:
		target.Tag = "!!bool"
	case KindInt:
		target.Tag = "!!int"
	default:
		target.Tag = "!!str"
	}

	return nil
}

// Save writes the file if it has not changed since it was read. It keeps a
// copy of the previous content (<file>.bak) and writes a temporary file that
// replaces the original, so a failure does not leave a broken configuration.
func (f *File) Save() error {
	current, err := os.ReadFile(f.Path)
	if err != nil {
		return err
	}
	if version(current) != f.Version {
		return ErrConflict
	}

	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(&f.root); err != nil {
		return err
	}
	if err := encoder.Close(); err != nil {
		return err
	}

	// the backup and the temporary file need a writable directory; without
	// it, the file is written in place
	dir := filepath.Dir(f.Path)
	tmp, err := os.CreateTemp(dir, ".minioidc-config-*")
	if err != nil {
		return os.WriteFile(f.Path, out.Bytes(), f.mode)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(out.Bytes()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(f.mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.WriteFile(f.Path+".bak", current, f.mode); err != nil {
		return fmt.Errorf("backup: %w", err)
	}

	if err := os.Rename(tmp.Name(), f.Path); err != nil {
		return err
	}

	f.Version = version(out.Bytes())
	return nil
}

// Writable returns an error if the file cannot be written by the server
func Writable(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}

	return file.Close()
}

// child returns the value of a key of a mapping
func child(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}

	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}

	return nil
}

// Generate writes a configuration file with the running settings of the
// default configuration (without a file), to start using a file. The master
// key is not written: it is read from the environment.
func Generate(config *domain.Config) []byte {
	var b strings.Builder
	line := func(format string, args ...interface{}) { fmt.Fprintf(&b, format+"\n", args...) }
	quoted := func(value string) string { return strconv.Quote(value) }

	line("# The configuration of %s, generated by the admin web.", config.Name)
	line("# Run the server with MINIOIDC_CONFIG pointing to this file, and set")
	line("# MINIOIDC_MASTERKEY to the content of %s.", filepath.Join(config.DataDir, "masterkey"))
	line("masterkey: ${MINIOIDC_MASTERKEY}")
	line("issuer: %s", quoted(config.Issuer))
	line("audience: %s", quoted(config.Audience))
	line("private_rsa_key_path: %s", quoted(filepath.Join(config.DataDir, "private.pem")))
	line("sqlite:")
	line("  filepath: %s", quoted(config.SqliteFilepath))
	for _, use := range []string{"grants", "sessions", "mfa", "client_assertions", "users", "clients"} {
		line("  use_in_%s: true", use)
	}
	line("admin:")
	line("  enabled: %t", config.AdminEnabled)
	line("  group: %s", quoted(config.AdminGroup))

	// the editable settings, by section
	sections := map[string][]string{}
	var order []string
	for _, d := range Definitions {
		value := d.Running(config)
		if d.Kind == KindString {
			value = quoted(value)
		}

		section, key, nested := strings.Cut(d.Key, ".")
		if !nested {
			line("%s: %s", d.Key, value)
			continue
		}
		if _, ok := sections[section]; !ok {
			order = append(order, section)
		}
		sections[section] = append(sections[section], fmt.Sprintf("  %s: %s", key, value))
	}
	for _, section := range order {
		line("%s:", section)
		for _, entry := range sections[section] {
			line("%s", entry)
		}
	}

	return []byte(b.String())
}

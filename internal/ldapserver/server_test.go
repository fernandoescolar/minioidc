package ldapserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/fernandoescolar/minioidc/internal/stores"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/go-ldap/ldap/v3"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const (
	baseDN          = "dc=example,dc=com"
	serviceDN       = "cn=service,dc=example,dc=com"
	servicePassword = "service-password"
	password        = "user-password"
	aliceDN         = "uid=alice,ou=users,dc=example,dc=com"
	bobDN           = "uid=bob,ou=users,dc=example,dc=com"
)

type fixture struct {
	address   string
	bobSecret string
	server    *Server
}

func hash(t *testing.T, value string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(value), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func freeAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func newFixture(t *testing.T, configure func(*domain.Config)) *fixture {
	t.Helper()
	users := stores.NewUserStore()
	passwordHash := hash(t, password)
	for _, u := range []domain.UserData{
		{Subject: "1", PreferredUsername: "alice", Name: "Alice Smith", GivenName: "Alice", FamilyName: "Smith", Email: "alice@example.com", Groups: []string{"admin", "dev"}, PasswordHash: passwordHash},
		{Subject: "2", PreferredUsername: "bob", Email: "bob@example.com", Groups: []string{"dev"}, PasswordHash: passwordHash},
	} {
		if _, err := users.NewUser(u); err != nil {
			t.Fatal(err)
		}
	}

	// bob has MFA
	mfa := stores.NewMFACodeStore(users)
	bob, _ := users.GetUserByID("2")
	secret, _ := cryptography.NewTOTPSecret()
	if _, err := mfa.NewMFACode("mfa-bob", bob, secret, cryptography.TOTPMethod); err != nil {
		t.Fatal(err)
	}

	config := &domain.Config{
		UserStore:        users,
		MFACodeStore:     mfa,
		UserBlockedStore: stores.NewUserBlockedStore(),
		LDAPServer: &domain.LDAPServerConfig{
			Address:          freeAddress(t),
			BaseDN:           baseDN,
			BindDN:           serviceDN,
			BindPasswordHash: hash(t, servicePassword),
		},
	}
	if configure != nil {
		configure(config)
	}

	server, err := New(config, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Stop() })

	return &fixture{address: config.LDAPServer.Address, bobSecret: secret, server: server}
}

func (f *fixture) dial(t *testing.T) *ldap.Conn {
	t.Helper()
	conn, err := ldap.DialURL("ldap://" + f.address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func resultCode(err error) uint16 {
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		return ldapErr.ResultCode
	}
	return 0
}

func expectCode(t *testing.T, err error, code uint16) {
	t.Helper()
	if resultCode(err) != code {
		t.Fatalf("Expected LDAP result %d, got %v", code, err)
	}
}

func search(conn *ldap.Conn, base string, scope int, filter string, attributes ...string) ([]*ldap.Entry, error) {
	result, err := conn.Search(ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, 0, 0, false, filter, attributes, nil))
	if err != nil {
		return nil, err
	}
	return result.Entries, nil
}

func dns(entries []*ldap.Entry) []string {
	result := make([]string, 0, len(entries))
	for _, e := range entries {
		result = append(result, e.DN)
	}
	sort.Strings(result)
	return result
}

func expectDNs(t *testing.T, entries []*ldap.Entry, err error, expected ...string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(expected)
	got := dns(entries)
	if len(got) != len(expected) {
		t.Fatalf("Expected %v, got %v", expected, got)
	}
	for i := range got {
		if got[i] != expected[i] {
			t.Fatalf("Expected %v, got %v", expected, got)
		}
	}
}

func TestAnonymousAccess(t *testing.T) {
	f := newFixture(t, nil)
	conn := f.dial(t)

	// the root DSE is always public
	entries, err := search(conn, "", ldap.ScopeBaseObject, "(objectClass=*)")
	if err != nil || len(entries) != 1 || entries[0].GetAttributeValue("namingContexts") != baseDN {
		t.Fatalf("Unexpected root DSE: %v %v", entries, err)
	}

	_, err = search(conn, baseDN, ldap.ScopeWholeSubtree, "(objectClass=*)")
	expectCode(t, err, ldap.LDAPResultInsufficientAccessRights)

	anonymous := newFixture(t, func(c *domain.Config) { c.LDAPServer.AllowAnonymous = true })
	entries, err = search(anonymous.dial(t), baseDN, ldap.ScopeWholeSubtree, "(objectClass=inetOrgPerson)")
	expectDNs(t, entries, err, aliceDN, bobDN)
}

func TestServiceAccountSearches(t *testing.T) {
	f := newFixture(t, nil)
	conn := f.dial(t)

	expectCode(t, conn.Bind(serviceDN, "wrong"), ldap.LDAPResultInvalidCredentials)
	if err := conn.Bind("CN=Service, DC=example, DC=com", servicePassword); err != nil {
		t.Fatalf("Expected the service account to bind (DNs are case insensitive): %v", err)
	}

	entries, err := search(conn, baseDN, ldap.ScopeWholeSubtree, "(objectClass=inetOrgPerson)")
	expectDNs(t, entries, err, aliceDN, bobDN)

	entries, err = search(conn, baseDN, ldap.ScopeSingleLevel, "(objectClass=*)")
	expectDNs(t, entries, err, "ou=users,"+baseDN, "ou=groups,"+baseDN)

	entries, err = search(conn, "ou=groups,"+baseDN, ldap.ScopeSingleLevel, "(member=UID=alice,OU=users,DC=example,DC=com)")
	expectDNs(t, entries, err, "cn=admin,ou=groups,"+baseDN, "cn=dev,ou=groups,"+baseDN)

	entries, err = search(conn, baseDN, ldap.ScopeWholeSubtree, "(&(objectClass=person)(memberOf=cn=admin,ou=groups,dc=example,dc=com))")
	expectDNs(t, entries, err, aliceDN)

	entries, err = search(conn, baseDN, ldap.ScopeWholeSubtree, "(|(mail=BOB@example.com)(cn=*smi*))")
	expectDNs(t, entries, err, aliceDN, bobDN)

	entries, err = search(conn, baseDN, ldap.ScopeWholeSubtree, "(&(uid=*)(!(uid=bob)))")
	expectDNs(t, entries, err, aliceDN)

	// base scope and attribute selection
	entries, err = search(conn, aliceDN, ldap.ScopeBaseObject, "(objectClass=*)", "mail", "memberOf")
	expectDNs(t, entries, err, aliceDN)
	alice := entries[0]
	if alice.GetAttributeValue("mail") != "alice@example.com" || len(alice.GetAttributeValues("memberOf")) != 2 || alice.GetAttributeValue("cn") != "" {
		t.Errorf("Expected only the requested attributes: %+v", alice.Attributes)
	}

	entries, _ = search(conn, aliceDN, ldap.ScopeBaseObject, "(objectClass=*)")
	for _, a := range entries[0].Attributes {
		if a.Name == "userPassword" {
			t.Fatal("The password must never be published")
		}
	}
	if entries[0].GetAttributeValue("employeeNumber") != "1" || entries[0].GetAttributeValue("sn") != "Smith" {
		t.Errorf("Unexpected attributes: %+v", entries[0].Attributes)
	}

	_, err = search(conn, "ou=other,"+baseDN, ldap.ScopeWholeSubtree, "(objectClass=*)")
	expectCode(t, err, ldap.LDAPResultNoSuchObject)

	result, err := conn.Search(ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false, "(uid=*)", nil, nil))
	expectCode(t, err, ldap.LDAPResultSizeLimitExceeded)
	if result == nil || len(result.Entries) != 1 {
		t.Errorf("Expected one entry before the size limit: %v", result)
	}

	// the directory is read only
	err = conn.Modify(&ldap.ModifyRequest{DN: aliceDN, Changes: []ldap.Change{{Operation: ldap.ReplaceAttribute, Modification: ldap.PartialAttribute{Type: "mail", Vals: []string{"x@x"}}}}})
	expectCode(t, err, ldap.LDAPResultUnwillingToPerform)
	expectCode(t, conn.Del(ldap.NewDelRequest(aliceDN, nil)), ldap.LDAPResultUnwillingToPerform)
	add := ldap.NewAddRequest("uid=eve,ou=users,"+baseDN, nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	expectCode(t, conn.Add(add), ldap.LDAPResultUnwillingToPerform)
}

func TestUserBind(t *testing.T) {
	f := newFixture(t, nil)
	conn := f.dial(t)

	if err := conn.Bind(aliceDN, password); err != nil {
		t.Fatalf("Expected alice to bind: %v", err)
	}

	// a user only reads their own entry
	entries, err := search(conn, baseDN, ldap.ScopeWholeSubtree, "(objectClass=*)")
	expectDNs(t, entries, err, aliceDN)

	if err := conn.Bind("alice", password); err != nil {
		t.Fatalf("Expected alice to bind with the username: %v", err)
	}

	expectCode(t, conn.Bind(aliceDN, "wrong"), ldap.LDAPResultInvalidCredentials)
	expectCode(t, conn.Bind("uid=alice,ou=other,dc=example,dc=com", password), ldap.LDAPResultInvalidCredentials)
	expectCode(t, conn.Bind("uid=nobody,ou=users,dc=example,dc=com", password), ldap.LDAPResultInvalidCredentials)

	// an unauthenticated bind (a name without password) is not a login
	if err := conn.UnauthenticatedBind(aliceDN); resultCode(err) != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("Expected the unauthenticated bind to fail: %v", err)
	}

	// a failed bind resets the identity
	_, err = search(conn, baseDN, ldap.ScopeWholeSubtree, "(objectClass=*)")
	expectCode(t, err, ldap.LDAPResultInsufficientAccessRights)

	searcher := newFixture(t, func(c *domain.Config) { c.LDAPServer.UsersCanSearch = true })
	other := searcher.dial(t)
	if err := other.Bind(aliceDN, password); err != nil {
		t.Fatal(err)
	}
	entries, err = search(other, baseDN, ldap.ScopeWholeSubtree, "(objectClass=inetOrgPerson)")
	expectDNs(t, entries, err, aliceDN, bobDN)
}

func TestUserBindWithMFA(t *testing.T) {
	f := newFixture(t, nil)
	conn := f.dial(t)

	// bob has MFA: the password alone is not enough
	expectCode(t, conn.Bind(bobDN, password), ldap.LDAPResultInvalidCredentials)

	code, err := totp.GenerateCode(f.bobSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	expectCode(t, conn.Bind(bobDN, password+wrongCode(code)), ldap.LDAPResultInvalidCredentials)
	if err := conn.Bind(bobDN, password+code); err != nil {
		t.Fatalf("Expected bob to bind with the TOTP code: %v", err)
	}

	// when MFA is required, the users without MFA cannot bind
	required := newFixture(t, func(c *domain.Config) { c.RequireMFA = true })
	expectCode(t, required.dial(t).Bind(aliceDN, password), ldap.LDAPResultInvalidCredentials)
}

func wrongCode(code string) string {
	if code == "123456" {
		return "654321"
	}
	return "123456"
}

func TestBruteForceProtection(t *testing.T) {
	f := newFixture(t, nil)
	conn := f.dial(t)

	for i := 0; i < stores.DefaultMaxFailedAttempts; i++ {
		_ = conn.Bind(aliceDN, "wrong")
	}

	// blocked, even with the right password
	expectCode(t, conn.Bind(aliceDN, password), ldap.LDAPResultInvalidCredentials)
}

func writeCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)

	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	return certPath, keyPath
}

func TestStartTLS(t *testing.T) {
	cert, key := writeCertificate(t)
	f := newFixture(t, func(c *domain.Config) {
		c.LDAPServer.TLSMode, c.LDAPServer.TLSCertPath, c.LDAPServer.TLSKeyPath = domain.LDAPTLSStartTLS, cert, key
	})

	conn := f.dial(t)
	expectCode(t, conn.Bind(aliceDN, password), ldap.LDAPResultConfidentialityRequired)

	if err := conn.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil { //nolint:gosec // self-signed test certificate
		t.Fatal(err)
	}
	if err := conn.Bind(aliceDN, password); err != nil {
		t.Fatalf("Expected the bind to work after StartTLS: %v", err)
	}
}

func TestLDAPS(t *testing.T) {
	cert, key := writeCertificate(t)
	f := newFixture(t, func(c *domain.Config) {
		c.LDAPServer.TLSMode, c.LDAPServer.TLSCertPath, c.LDAPServer.TLSKeyPath = domain.LDAPTLSLDAPS, cert, key
	})

	conn, err := ldap.DialURL("ldaps://"+f.address, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true})) //nolint:gosec // self-signed test certificate
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := conn.Bind(serviceDN, servicePassword); err != nil {
		t.Fatalf("Expected the bind to work with LDAPS: %v", err)
	}
}

func TestInvalidConfiguration(t *testing.T) {
	users := stores.NewUserStore()
	for name, cfg := range map[string]domain.LDAPServerConfig{
		"invalid base dn":      {BaseDN: "not a dn"},
		"bind dn without hash": {BaseDN: baseDN, BindDN: serviceDN},
		"unknown tls mode":     {BaseDN: baseDN, TLSMode: "magic"},
		"missing certificate":  {BaseDN: baseDN, TLSMode: domain.LDAPTLSLDAPS, TLSCertPath: "missing.pem", TLSKeyPath: "missing.pem"},
	} {
		cfg := cfg
		if _, err := New(&domain.Config{UserStore: users, LDAPServer: &cfg}, time.Now); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

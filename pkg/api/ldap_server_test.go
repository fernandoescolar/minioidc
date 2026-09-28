package api_test

import (
	"net"
	"net/http"
	"testing"

	"github.com/fernandoescolar/minioidc/pkg/api"
	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/go-ldap/ldap/v3"
)

// The users created in the admin web are served by the LDAP server at once
func TestLDAPServerServesTheUsersOfTheDatabase(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	l.Close()

	s := newTestServer(t, false, withAdmin(t.TempDir()+"/ldap.sqlite3"), func(b *api.Builder) {
		b.LDAPServer = &domain.LDAPServerConfig{Address: address, BaseDN: "dc=example,dc=com", AllowAnonymous: true}
	})
	if err := s.minioidc.StartLDAPServer(); err != nil {
		t.Fatal(err)
	}

	admin := s.loginAs(t, username)
	admin.call(http.MethodPost, "/users", map[string]interface{}{
		"preferred_username": "dave", "email": "dave@example.com", "password": "dave-password", "groups": []string{"media"},
	}, http.StatusCreated, nil)

	conn, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	result, err := conn.Search(ldap.NewSearchRequest("dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=inetOrgPerson)(memberOf=cn=media,ou=groups,dc=example,dc=com))", []string{"mail"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 1 || result.Entries[0].GetAttributeValue("mail") != "dave@example.com" {
		t.Fatalf("Expected the new user in the directory: %v", result.Entries)
	}

	if err := conn.Bind("uid=dave,ou=users,dc=example,dc=com", "dave-password"); err != nil {
		t.Fatalf("Expected the new user to bind: %v", err)
	}
}

func TestLDAPServerConfiguration(t *testing.T) {
	for name, configure := range map[string]func(*api.Builder){
		"without base dn": func(b *api.Builder) { b.LDAPServer = &domain.LDAPServerConfig{} },
		"with LDAP users": func(b *api.Builder) {
			b.LDAPServer = &domain.LDAPServerConfig{BaseDN: "dc=example,dc=com"}
			b.UseLDAP("ldap.example.com:389", api.LDAPConfig{Bind: "cn=x", Password: "x", FilterDN: "(uid={username})", BaseDN: "dc=x",
				SubjectAttribute: "uid", NameAttribute: "uid", EmailAttribute: "mail", PhoneAttribute: "tel", AddressAttribute: "addr"})
		},
		"tls without certificate": func(b *api.Builder) {
			b.LDAPServer = &domain.LDAPServerConfig{BaseDN: "dc=example,dc=com", TLSMode: "ldaps"}
		},
	} {
		b := &api.Builder{Issuer: issuer, Audience: audience}
		configure(b)
		if _, err := b.Build(); err == nil {
			t.Errorf("%s: expected a configuration error", name)
		}
	}
}

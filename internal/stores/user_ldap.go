package stores

import (
	"fmt"
	"strings"

	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/go-ldap/ldap/v3"
)

// const (
// 	ldapServer   = "ad.example.com:389"
// 	ldapBind     = "search@example.com"
// 	ldapPassword = "Password123!"

// 	filterDN = "(&(objectClass=person)(memberOf:1.2.840.113556.1.4.1941:=CN=Chat,CN=Users,DC=example,DC=com)(|(sAMAccountName={username})(mail={username})))"
// 	baseDN   = "CN=Users,DC=example,DC=com"
// )

type ldapUserStore struct {
	ldapServer   string
	ldapBind     string
	ldapPassword string

	filterDN string
	baseDN   string

	subjectAttribute string
	nameAttribute    string
	emailAttribute   string
	phoneAttribute   string
	addressAttribute string

	connection *ldap.Conn
}

func NewLDAPUserStore(
	ldapServer string,
	ldapBind string,
	ldapPassword string,
	filterDN string,
	baseDN string,
	subjectAttribute string,
	nameAttribute string,
	emailAttribute string,
	phoneAttribute string,
	addressAttribute string,
) domain.UserStore {
	s := &ldapUserStore{
		ldapServer:       ldapServer,
		ldapBind:         ldapBind,
		ldapPassword:     ldapPassword,
		filterDN:         filterDN,
		baseDN:           baseDN,
		subjectAttribute: subjectAttribute,
		nameAttribute:    nameAttribute,
		emailAttribute:   emailAttribute,
		phoneAttribute:   phoneAttribute,
		addressAttribute: addressAttribute,
	}

	if err := s.connect(); err != nil {
		panic(err)
	}

	return s
}

func (us *ldapUserStore) NewUser(subject, email, preferredUsername, phone, address string, groups []string, passwordHash string) (domain.User, error) {
	return nil, nil
}

func (us *ldapUserStore) GetUserByID(id string) (domain.User, error) {
	users, err := us.list()
	if err != nil {
		return nil, err
	}

	user, ok := users[id]
	if !ok {
		return nil, fmt.Errorf("User not found")
	}

	return user, nil
}

func (us *ldapUserStore) GetUserByUsernameAndPassword(username, password string) (domain.User, error) {
	return us.auth(username, password)
}

func (us *ldapUserStore) connect() error {
	conn, err := ldap.Dial("tcp", us.ldapServer)

	if err != nil {
		return fmt.Errorf("Failed to connect. %s", err)
	}

	if err := conn.Bind(us.ldapBind, us.ldapPassword); err != nil {
		return fmt.Errorf("Failed to bind. %s", err)
	}

	us.connection = conn
	return nil
}

func (us *ldapUserStore) list() (map[string]domain.User, error) {
	result, err := us.connection.Search(ldap.NewSearchRequest(
		us.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		us.filter("*"),
		[]string{us.subjectAttribute, us.nameAttribute, us.emailAttribute, us.phoneAttribute, us.addressAttribute},
		nil,
	))

	if err != nil {
		return nil, fmt.Errorf("Failed to search users. %s", err)
	}

	users := make(map[string]domain.User)
	for _, entry := range result.Entries {
		u := us.User(entry)
		users[u.ID()] = u
	}

	return users, nil
}

func (us *ldapUserStore) auth(username, password string) (domain.User, error) {
	result, err := us.connection.Search(ldap.NewSearchRequest(
		us.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		us.filter(username),
		[]string{us.subjectAttribute, us.nameAttribute, us.emailAttribute, us.phoneAttribute, us.addressAttribute},
		nil,
	))

	if err != nil {
		return nil, fmt.Errorf("Failed to find user. %s", err)
	}

	if len(result.Entries) < 1 {
		return nil, fmt.Errorf("User does not exist")
	}

	if len(result.Entries) > 1 {
		return nil, fmt.Errorf("Too many entries returned")
	}

	if err := us.connection.Bind(result.Entries[0].DN, password); err != nil {
		return nil, fmt.Errorf("Failed to auth user. %s", err)
	}

	return us.User(result.Entries[0]), nil
}

func (us *ldapUserStore) filter(needle string) string {
	res := strings.Replace(
		us.filterDN,
		"{username}",
		needle,
		-1,
	)

	return res
}

func (us *ldapUserStore) User(e *ldap.Entry) domain.User {
	return domain.NewUser(
		e.GetAttributeValue(us.subjectAttribute),
		e.GetAttributeValue(us.emailAttribute),
		e.GetAttributeValue(us.nameAttribute),
		e.GetAttributeValue(us.phoneAttribute),
		e.GetAttributeValue(us.addressAttribute),
		[]string{},
		"",
	)
}

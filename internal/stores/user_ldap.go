package stores

import (
	"fmt"
	"log"
	"strings"

	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/go-ldap/ldap/v3"
)

// LDAPConfig is the configuration of the LDAP user store
type LDAPConfig struct {
	Server   string
	Bind     string
	Password string
	FilterDN string
	BaseDN   string

	// SubjectAttribute is the attribute used as subject (sub claim)
	SubjectAttribute string
	// NameAttribute is the attribute used as preferred_username
	NameAttribute string
	// DisplayNameAttribute, GivenNameAttribute and FamilyNameAttribute are optional
	DisplayNameAttribute string
	GivenNameAttribute   string
	FamilyNameAttribute  string
	EmailAttribute       string
	PhoneAttribute       string
	AddressAttribute     string
	// GroupsAttribute is optional (e.g. memberOf)
	GroupsAttribute string

	// EmailVerified must be true only if the directory verifies the emails
	EmailVerified bool
}

type ldapUserStore struct {
	config LDAPConfig
}

func NewLDAPUserStore(config LDAPConfig) domain.UserStore {
	return &ldapUserStore{config: config}
}

func (us *ldapUserStore) NewUser(_ domain.UserData) (domain.User, error) {
	return nil, fmt.Errorf("Not implemented")
}

func (us *ldapUserStore) GetUserByID(id string) (domain.User, error) {
	connection, err := us.connect()
	if err != nil {
		return nil, err
	}

	defer connection.Close()
	filter := fmt.Sprintf("(&%s(%s=%s))", us.filter("*"), ldap.EscapeFilter(us.config.SubjectAttribute), ldap.EscapeFilter(id))
	result, err := connection.Search(ldap.NewSearchRequest(
		us.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		filter,
		us.attributes(),
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("Failed to search user. %w", err)
	}

	if len(result.Entries) != 1 {
		return nil, fmt.Errorf("User not found")
	}

	return us.User(result.Entries[0]), nil
}

func (us *ldapUserStore) GetUserByUsernameAndPassword(username, password string) (domain.User, error) {
	return us.auth(username, password)
}

func (us *ldapUserStore) connect() (*ldap.Conn, error) {
	conn, err := ldap.Dial("tcp", us.config.Server)

	if err != nil {
		log.Printf("Failed to connect to ldap: %s", err)
		return nil, fmt.Errorf("Failed to connect. %w", err)
	}

	if err := conn.Bind(us.config.Bind, us.config.Password); err != nil {
		log.Printf("Invalid ldap credentials: %s", err)
		return nil, fmt.Errorf("Failed to bind. %w", err)
	}

	return conn, nil
}

func (us *ldapUserStore) auth(username, password string) (domain.User, error) {
	// an empty password is an unauthenticated bind: most servers accept it
	if username == "" || password == "" {
		return nil, fmt.Errorf("Username and password are required")
	}

	connection, err := us.connect()
	if err != nil {
		return nil, err
	}

	defer connection.Close()
	result, err := connection.Search(ldap.NewSearchRequest(
		us.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		us.filter(ldap.EscapeFilter(username)),
		us.attributes(),
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

	if err := connection.Bind(result.Entries[0].DN, password); err != nil {
		return nil, fmt.Errorf("Failed to auth user. %s", err)
	}

	return us.User(result.Entries[0]), nil
}

func (us *ldapUserStore) attributes() []string {
	attributes := []string{"dn"}
	for _, a := range []string{
		us.config.SubjectAttribute, us.config.NameAttribute, us.config.DisplayNameAttribute, us.config.GivenNameAttribute,
		us.config.FamilyNameAttribute, us.config.EmailAttribute, us.config.PhoneAttribute, us.config.AddressAttribute,
		us.config.GroupsAttribute,
	} {
		if a != "" {
			attributes = append(attributes, a)
		}
	}

	return attributes
}

// filter replaces {username} in the filter. The needle must be already escaped.
func (us *ldapUserStore) filter(needle string) string {
	res := strings.Replace(
		us.config.FilterDN,
		"{username}",
		needle,
		-1,
	)

	return res
}

func (us *ldapUserStore) User(e *ldap.Entry) domain.User {
	groups := []string{}
	if us.config.GroupsAttribute != "" {
		groups = append(groups, e.GetAttributeValues(us.config.GroupsAttribute)...)
	}

	value := func(attribute string) string {
		if attribute == "" {
			return ""
		}

		return e.GetAttributeValue(attribute)
	}

	return domain.NewUser(domain.UserData{
		Subject:           value(us.config.SubjectAttribute),
		Email:             value(us.config.EmailAttribute),
		EmailVerified:     us.config.EmailVerified,
		PreferredUsername: value(us.config.NameAttribute),
		Name:              value(us.config.DisplayNameAttribute),
		GivenName:         value(us.config.GivenNameAttribute),
		FamilyName:        value(us.config.FamilyNameAttribute),
		Phone:             value(us.config.PhoneAttribute),
		Address:           value(us.config.AddressAttribute),
		Groups:            groups,
	})
}

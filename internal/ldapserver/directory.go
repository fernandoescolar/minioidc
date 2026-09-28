package ldapserver

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/go-ldap/ldap/v3"
)

// entry is an LDAP entry. The attribute names are kept with their case, but
// they are compared case insensitively.
type entry struct {
	dn         string
	parsedDN   *ldap.DN
	attributes map[string][]string
}

func newEntry(dn string, attributes map[string][]string) *entry {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		// the DNs are built by the directory: they are always valid
		panic(fmt.Sprintf("invalid DN %q: %v", dn, err))
	}

	return &entry{dn: dn, parsedDN: parsed, attributes: attributes}
}

// values returns the values of an attribute (case insensitive name)
func (e *entry) values(name string) []string {
	for key, values := range e.attributes {
		if strings.EqualFold(key, name) {
			return values
		}
	}

	return nil
}

// directory is a snapshot of the users and groups as LDAP entries:
//
//	<base dn>
//	├── ou=users   uid=<username> (inetOrgPerson)
//	└── ou=groups  cn=<group>     (groupOfNames)
type directory struct {
	base    *entry
	entries []*entry
}

func buildDirectory(baseDN string, users []domain.UserData) *directory {
	usersDN := "ou=users," + baseDN
	groupsDN := "ou=groups," + baseDN

	members := map[string][]string{}
	var entries []*entry
	base := newEntry(baseDN, baseAttributes(baseDN))
	entries = append(entries,
		base,
		newEntry(usersDN, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"users"}}),
		newEntry(groupsDN, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"groups"}}),
	)

	for _, u := range users {
		dn := userDN(u.PreferredUsername, baseDN)
		var memberOf []string
		for _, g := range u.Groups {
			members[g] = append(members[g], dn)
			memberOf = append(memberOf, groupDN(g, baseDN))
		}

		entries = append(entries, newEntry(dn, userAttributes(u, memberOf)))
	}

	groups := make([]string, 0, len(members))
	for g := range members {
		groups = append(groups, g)
	}
	sort.Strings(groups)

	for _, g := range groups {
		entries = append(entries, newEntry(groupDN(g, baseDN), map[string][]string{
			"objectClass": {"top", "groupOfNames"},
			"cn":          {g},
			"member":      members[g],
		}))
	}

	return &directory{base: base, entries: entries}
}

func userDN(username, baseDN string) string {
	return "uid=" + ldap.EscapeDN(username) + ",ou=users," + baseDN
}

func groupDN(group, baseDN string) string {
	return "cn=" + ldap.EscapeDN(group) + ",ou=groups," + baseDN
}

// baseAttributes describes the base entry from its first RDN (e.g. dc=example)
func baseAttributes(baseDN string) map[string][]string {
	attributes := map[string][]string{"objectClass": {"top"}}
	parsed, err := ldap.ParseDN(baseDN)
	if err != nil || len(parsed.RDNs) == 0 || len(parsed.RDNs[0].Attributes) == 0 {
		return attributes
	}

	first := parsed.RDNs[0].Attributes[0]
	attributes[first.Type] = []string{first.Value}
	switch strings.ToLower(first.Type) {
	case "dc":
		attributes["objectClass"] = append(attributes["objectClass"], "domain")
	case "o":
		attributes["objectClass"] = append(attributes["objectClass"], "organization")
	case "ou":
		attributes["objectClass"] = append(attributes["objectClass"], "organizationalUnit")
	}

	return attributes
}

// userAttributes maps a user to an inetOrgPerson. The password is never published.
func userAttributes(u domain.UserData, memberOf []string) map[string][]string {
	cn := firstNonEmpty(u.Name, u.PreferredUsername)
	attributes := map[string][]string{
		"objectClass": {"top", "person", "organizationalPerson", "inetOrgPerson"},
		"uid":         {u.PreferredUsername},
		"cn":          {cn},
		// sn is required by the person object class
		"sn":          {firstNonEmpty(u.FamilyName, cn)},
		"displayName": {cn},
		// the OIDC subject, so the applications can match the LDAP and OIDC users
		"employeeNumber": {u.Subject},
	}

	optional := map[string]string{
		"givenName":       u.GivenName,
		"mail":            u.Email,
		"telephoneNumber": u.Phone,
		"postalAddress":   u.Address,
	}
	for name, value := range optional {
		if value != "" {
			attributes[name] = []string{value}
		}
	}

	if len(memberOf) > 0 {
		attributes["memberOf"] = memberOf
	}

	return attributes
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}

	return ""
}

package ldapserver

import (
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// compileFilter parses an LDAP filter (RFC 4515)
func compileFilter(filter string) (*ber.Packet, error) {
	if strings.TrimSpace(filter) == "" {
		filter = "(objectClass=*)"
	}

	return ldap.CompileFilter(filter)
}

// matches evaluates a compiled filter against an entry. The values are
// compared case insensitively (the attributes of the directory are strings
// with case insensitive matching rules, except the DNs that are normalized).
func matches(filter *ber.Packet, e *entry) bool {
	switch filter.Tag {
	case ldap.FilterAnd:
		for _, child := range filter.Children {
			if !matches(child, e) {
				return false
			}
		}
		return true
	case ldap.FilterOr:
		for _, child := range filter.Children {
			if matches(child, e) {
				return true
			}
		}
		return false
	case ldap.FilterNot:
		return len(filter.Children) == 1 && !matches(filter.Children[0], e)
	case ldap.FilterPresent:
		return len(e.values(decode(filter))) > 0
	case ldap.FilterEqualityMatch, ldap.FilterApproxMatch:
		name, value := assertion(filter)
		return anyValue(e, name, func(v string) bool { return equalValues(name, v, value) })
	case ldap.FilterGreaterOrEqual:
		name, value := assertion(filter)
		return anyValue(e, name, func(v string) bool { return strings.ToLower(v) >= strings.ToLower(value) })
	case ldap.FilterLessOrEqual:
		name, value := assertion(filter)
		return anyValue(e, name, func(v string) bool { return strings.ToLower(v) <= strings.ToLower(value) })
	case ldap.FilterSubstrings:
		return matchesSubstrings(filter, e)
	default:
		// extensible matches are not supported: they never match
		return false
	}
}

func decode(p *ber.Packet) string {
	return ber.DecodeString(p.Data.Bytes())
}

func assertion(filter *ber.Packet) (string, string) {
	if len(filter.Children) != 2 {
		return "", ""
	}

	return decode(filter.Children[0]), decode(filter.Children[1])
}

func anyValue(e *entry, name string, match func(string) bool) bool {
	for _, v := range e.values(name) {
		if match(v) {
			return true
		}
	}

	return false
}

// equalValues compares two values. The DN attributes (member, memberOf) are
// compared as DNs, so "uid=a,dc=x" matches "UID=a, DC=x".
func equalValues(attribute, a, b string) bool {
	switch strings.ToLower(attribute) {
	case "member", "memberof", "uniquemember":
		da, errA := ldap.ParseDN(a)
		db, errB := ldap.ParseDN(b)
		if errA == nil && errB == nil {
			return da.EqualFold(db)
		}
	}

	return strings.EqualFold(a, b)
}

func matchesSubstrings(filter *ber.Packet, e *entry) bool {
	if len(filter.Children) != 2 {
		return false
	}

	name := decode(filter.Children[0])
	parts := filter.Children[1].Children
	return anyValue(e, name, func(value string) bool {
		value = strings.ToLower(value)
		for i, part := range parts {
			text := strings.ToLower(decode(part))
			switch part.Tag {
			case ldap.FilterSubstringsInitial:
				if i != 0 || !strings.HasPrefix(value, text) {
					return false
				}
				value = value[len(text):]
			case ldap.FilterSubstringsAny:
				index := strings.Index(value, text)
				if index < 0 {
					return false
				}
				value = value[index+len(text):]
			case ldap.FilterSubstringsFinal:
				if !strings.HasSuffix(value, text) {
					return false
				}
				value = ""
			}
		}

		return true
	})
}

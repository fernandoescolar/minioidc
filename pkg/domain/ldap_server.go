package domain

// LDAP server TLS modes
const (
	LDAPTLSNone     = ""
	LDAPTLSLDAPS    = "ldaps"
	LDAPTLSStartTLS = "starttls"
)

// LDAPServerConfig is the configuration of the read only LDAP directory that
// minioidc serves with its users (from SQLite or the configuration file)
type LDAPServerConfig struct {
	// Address to listen on (e.g. ":3389")
	Address string
	// BaseDN of the directory (e.g. "dc=example,dc=com"). The users are in
	// ou=users,<base dn> and the groups in ou=groups,<base dn>.
	BaseDN string
	// BindDN and BindPasswordHash (bcrypt) are the service account the
	// applications use to search the directory. Optional.
	BindDN           string
	BindPasswordHash string
	// AllowAnonymous lets anonymous clients search the directory
	AllowAnonymous bool
	// UsersCanSearch lets the users bound with their own credentials search
	// all the directory. Otherwise, they can only read their own entry.
	UsersCanSearch bool
	// TLSMode is "" (plain LDAP), "ldaps" or "starttls"
	TLSMode     string
	TLSCertPath string
	TLSKeyPath  string
}

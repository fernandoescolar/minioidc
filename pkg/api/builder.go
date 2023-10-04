package api

import (
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/fernandoescolar/minioidc/internal/db"
	"github.com/fernandoescolar/minioidc/internal/stores"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type SqliteDatabases int

const (
	NoSqliteDatabases SqliteDatabases = 0
	Grants                            = 1
	Sessions                          = 2
	MFA                               = 4
	All               SqliteDatabases = Grants | Sessions | MFA
)

type Builder struct {
	Name                  string
	MasterKey             string
	Issuer                string
	Audience              string
	RequireMFA            bool
	ReuseRefreshTokens    bool
	PrivateRSAKeyFilepath string
	PrivateRSAKey         *rsa.PrivateKey

	UseHSTS             bool
	UseCSP              bool
	UseSecureCookie     bool
	UseForwardedHeaders bool
	LogRequests         bool

	AccessTTL  time.Duration
	RefreshTTL time.Duration
	SessionTTL time.Duration
	CodeTTL    time.Duration
	CSRFTTL    time.Duration

	BaseTemplateFilepath      string
	LoginTemplateFilepath     string
	MFACreateTemplateFilepath string
	MFAVerifyTemplateFilepath string

	ClientStore  domain.ClientStore
	GrantStore   domain.GrantStore
	SessionStore domain.SessionStore
	UserStore    domain.UserStore
	MFACodeStore domain.MFACodeStore

	sqliteFilepath      string
	sqliteUseInGrants   bool
	sqliteUseInSessions bool
	sqliteUseInMFA      bool

	ldapServer           string
	ldapBind             string
	ldapPassword         string
	ldapFilterDN         string
	ldapBaseDN           string
	ldapSubjectAttribute string
	ldapNameAttribute    string
	ldapEmailAttribute   string
	ldapPhoneAttribute   string
	ldapAddressAttribute string

	Clients []Client
	Users   []User
}

type LDAPConfig struct {
	Bind             string
	Password         string
	FilterDN         string
	BaseDN           string
	SubjectAttribute string
	NameAttribute    string
	EmailAttribute   string
	PhoneAttribute   string
	AddressAttribute string
}

type Client struct {
	ID           string
	SecretHash   string
	RedirectURIs []string
}

type User struct {
	Subject           string
	Email             string
	PreferredUsername string
	PasswordHash      string
	Phone             string
	Address           string
	Groups            []string
}

// UseSQLite sets the sqlite filepath and the databases where it will be used
func (b *Builder) UseSQLite(f string, d SqliteDatabases) {
	b.sqliteFilepath = f
	b.sqliteUseInGrants = false
	b.sqliteUseInSessions = false
	b.sqliteUseInMFA = false

	if d&Grants == Grants {
		b.sqliteUseInGrants = true
	}
	if d&Sessions == Sessions {
		b.sqliteUseInSessions = true
	}
	if d&MFA == MFA {
		b.sqliteUseInMFA = true
	}
}

// UseLDAP sets the LDAP connection parameters
func (b *Builder) UseLDAP(server string, c LDAPConfig) {
	b.ldapServer = server
	b.ldapBind = c.Bind
	b.ldapPassword = c.Password
	b.ldapFilterDN = c.FilterDN
	b.ldapBaseDN = c.BaseDN
	b.ldapSubjectAttribute = c.SubjectAttribute
	b.ldapNameAttribute = c.NameAttribute
	b.ldapEmailAttribute = c.EmailAttribute
	b.ldapPhoneAttribute = c.PhoneAttribute
	b.ldapAddressAttribute = c.AddressAttribute
}

// builds the server
func (b *Builder) Build() (*Minioidc, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}

	if err := b.assignDefaults(); err != nil {
		return nil, err
	}

	config, err := b.config()
	if err != nil {
		return nil, err
	}

	return NewMinioidc(config), nil
}

func (b *Builder) validate() error {
	if b.Issuer == "" {
		return errors.New("issuer is required")
	}
	if b.Audience == "" {
		return errors.New("audience is required")
	}
	if b.PrivateRSAKeyFilepath != "" && b.PrivateRSAKey != nil {
		return errors.New("private key and private key filepath are mutually exclusive")
	}
	if b.sqliteFilepath == "" && (b.sqliteUseInGrants || b.sqliteUseInSessions) {
		return errors.New("sqlite filepath is required")
	}
	if b.sqliteUseInGrants && b.GrantStore != nil {
		return errors.New("sqlite grant store and grant store are mutually exclusive")
	}
	if b.sqliteUseInSessions && b.SessionStore != nil {
		return errors.New("sqlite session store and session store are mutually exclusive")
	}
	if b.ldapServer != "" && b.UserStore != nil {
		return errors.New("ldap and user store are mutually exclusive")
	}
	if b.ldapServer != "" {
		if b.ldapBind == "" {
			return errors.New("ldap bind is required")
		}
		if b.ldapPassword == "" {
			return errors.New("ldap password is required")
		}
		if b.ldapFilterDN == "" {
			return errors.New("ldap filter dn is required")
		}
		if b.ldapBaseDN == "" {
			return errors.New("ldap base dn is required")
		}
		if b.ldapSubjectAttribute == "" {
			return errors.New("ldap subject attribute is required")
		}
		if b.ldapNameAttribute == "" {
			return errors.New("ldap name attribute is required")
		}
		if b.ldapEmailAttribute == "" {
			return errors.New("ldap email attribute is required")
		}
		if b.ldapPhoneAttribute == "" {
			return errors.New("ldap phone attribute is required")
		}
		if b.ldapAddressAttribute == "" {
			return errors.New("ldap address attribute is required")
		}
	}

	return nil
}

const (
	defaultAccessTTL  = 20
	defaultRefreshTTL = 129600
	defaultSessionTTL = 129600
	defaultCodeTTL    = 5
	defaultCSRFTTL    = 5
	defaultRSASize    = 2048
)

func (b *Builder) assignDefaults() error {
	if b.Name == "" {
		b.Name = "minioidc"
	}
	if b.MasterKey == "" {
		masterKey, err := cryptography.RandomPassword(16)
		if err != nil {
			return fmt.Errorf("cannot create random masterkey: %w", err)
		}

		b.MasterKey = masterKey
	}
	if b.PrivateRSAKeyFilepath == "" && b.PrivateRSAKey == nil {
		rk, err := rsa.GenerateKey(rand.Reader, defaultRSASize)
		if err != nil {
			return fmt.Errorf("random keypair: %w", err)
		}

		b.PrivateRSAKey = rk
	}
	if b.AccessTTL == 0 {
		b.AccessTTL = defaultAccessTTL * time.Minute
	}
	if b.RefreshTTL == 0 {
		b.RefreshTTL = defaultRefreshTTL * time.Minute
	}
	if b.SessionTTL == 0 {
		b.SessionTTL = defaultSessionTTL * time.Minute
	}
	if b.CodeTTL == 0 {
		b.CodeTTL = defaultCodeTTL * time.Minute
	}
	if b.CSRFTTL == 0 {
		b.CSRFTTL = defaultCSRFTTL * time.Minute
	}
	if b.BaseTemplateFilepath == "" {
		b.BaseTemplateFilepath = "templates/base.html"
	}
	if b.LoginTemplateFilepath == "" {
		b.LoginTemplateFilepath = "templates/login.html"
	}
	if b.MFACreateTemplateFilepath == "" {
		b.MFACreateTemplateFilepath = "templates/mfa_create.html"
	}
	if b.MFAVerifyTemplateFilepath == "" {
		b.MFAVerifyTemplateFilepath = "templates/mfa_verify.html"
	}

	return nil
}

func (b *Builder) config() (*domain.Config, error) {
	config := &domain.Config{
		Name:               b.Name,
		MasterKey:          b.MasterKey,
		Issuer:             b.Issuer,
		Audience:           b.Audience,
		RequireMFA:         b.RequireMFA,
		ReuseRefreshTokens: b.ReuseRefreshTokens,

		UseHSTS:             b.UseHSTS,
		UseCSP:              b.UseCSP,
		UseSecureCookie:     b.UseSecureCookie,
		UseForwardedHeaders: b.UseForwardedHeaders,
		LogRequests:         b.LogRequests,

		AccessTTL:  b.AccessTTL,
		RefreshTTL: b.RefreshTTL,
		SessionTTL: b.SessionTTL,
		CodeTTL:    b.CodeTTL,
		CSRFTTL:    b.CSRFTTL,

		BaseTemplateFilepath:      b.BaseTemplateFilepath,
		LoginTemplateFilepath:     b.LoginTemplateFilepath,
		MFACreateTemplateFilepath: b.MFACreateTemplateFilepath,
		MFAVerifyTemplateFilepath: b.MFAVerifyTemplateFilepath,
	}

	if err := b.assignPrivateKey(config); err != nil {
		return nil, err
	}

	if err := b.assignStores(config); err != nil {
		return nil, err
	}

	if err := b.seedData(config); err != nil {
		return nil, err
	}

	return config, nil
}

func (b *Builder) assignPrivateKey(config *domain.Config) error {
	if b.PrivateRSAKey != nil {
		keypair, err := cryptography.NewKeypair(b.PrivateRSAKey)
		if err != nil {
			return fmt.Errorf("keypair: %w", err)
		}

		config.Keypair = keypair
	}

	if b.PrivateRSAKeyFilepath != "" {
		rsaKey, err := cryptography.LoadPrivateKey(b.PrivateRSAKeyFilepath)
		if err != nil {
			return fmt.Errorf("load private key: %w", err)
		}

		keypair, err := cryptography.NewKeypair(rsaKey)
		if err != nil {
			return fmt.Errorf("keypair: %w", err)
		}

		config.Keypair = keypair
	}

	return nil
}

func (b *Builder) assignStores(config *domain.Config) error {
	var (
		clientStore  domain.ClientStore
		grantStore   domain.GrantStore
		sessionStore domain.SessionStore
		userStore    domain.UserStore
		mfaStore     domain.MFACodeStore
		sqlite       *sql.DB
		err          error
	)

	if b.sqliteFilepath != "" {
		sqlite, err = db.NewSqliteDB(b.sqliteFilepath)
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
	}

	switch {
	case b.ldapServer != "":
		userStore = stores.NewLDAPUserStore(
			b.ldapServer,
			b.ldapBind,
			b.ldapPassword,
			b.ldapFilterDN,
			b.ldapBaseDN,
			b.ldapSubjectAttribute,
			b.ldapNameAttribute,
			b.ldapEmailAttribute,
			b.ldapPhoneAttribute,
			b.ldapAddressAttribute,
		)
	case b.UserStore == nil:
		userStore = stores.NewUserStore()
	default:
		userStore = b.UserStore
	}

	if b.ClientStore == nil {
		clientStore = stores.NewClientStore()
	} else {
		clientStore = b.ClientStore
	}

	switch {
	case b.sqliteUseInSessions:
		sessionStore = stores.NewSqliteSessionStore(sqlite, userStore)
	case b.SessionStore == nil:
		sessionStore = stores.NewSessionStore(userStore)
	default:
		sessionStore = b.SessionStore
	}

	switch {
	case b.sqliteUseInGrants:
		grantStore = stores.NewSqliteGrantStore(sqlite, clientStore, sessionStore)
	case b.GrantStore == nil:
		grantStore = stores.NewGrantStore(clientStore, sessionStore)
	default:
		grantStore = b.GrantStore
	}

	switch {
	case b.sqliteUseInMFA:
		mfaStore = stores.NewSqliteMFACodeStore(sqlite, userStore)
	case b.MFACodeStore == nil:
		mfaStore = stores.NewMFACodeStore(userStore)
	default:
		mfaStore = b.MFACodeStore
	}

	config.ClientStore = clientStore
	config.GrantStore = grantStore
	config.SessionStore = sessionStore
	config.UserStore = userStore
	config.MFACodeStore = mfaStore

	return nil
}

func (b *Builder) seedData(config *domain.Config) error {
	if config.ClientStore != nil {
		if err := b.seedClients(config.ClientStore); err != nil {
			return err
		}
	}

	if config.UserStore != nil {
		if err := b.seedUsers(config.UserStore); err != nil {
			return err
		}
	}

	return nil
}

func (b *Builder) seedClients(clientStore domain.ClientStore) error {
	for _, c := range b.Clients {
		_, err := clientStore.NewClient(c.ID, c.SecretHash, c.RedirectURIs)
		if err != nil {
			return fmt.Errorf("seed clients: %w", err)
		}
	}

	return nil
}

func (b *Builder) seedUsers(userStore domain.UserStore) error {
	for _, u := range b.Users {
		_, err := userStore.NewUser(u.Subject, u.Email, u.PreferredUsername, u.Phone, u.Address, u.Groups, u.PasswordHash)
		if err != nil {
			return fmt.Errorf("seed users: %w", err)
		}
	}

	return nil
}

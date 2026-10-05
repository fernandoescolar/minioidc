package api

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
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
	ClientAssertions                  = 8
	Users                             = 16
	Clients                           = 32
	All               SqliteDatabases = Grants | Sessions | MFA | ClientAssertions | Users | Clients
)

type Builder struct {
	Name string
	// ConfigFilepath is the configuration file of the builder (NewYamlBuilder):
	// the admin web edits it
	ConfigFilepath string
	// DataDir is the data directory of the default configuration (NewDefaultBuilder)
	DataDir            string
	MasterKey          string
	Issuer             string
	Audience           string
	RequireMFA         bool
	ReuseRefreshTokens bool
	// AllowImplicitFlow and AllowPasswordGrant enable the discouraged flows
	// (RFC 9700) for the clients that list them in their grant types
	AllowImplicitFlow     bool
	AllowPasswordGrant    bool
	PrivateRSAKeyFilepath string
	PrivateRSAKey         *rsa.PrivateKey
	// keys used before a key rotation: they are published in the JWKS and
	// tokens signed with them are still accepted (PEM public or private keys)
	PreviousRSAKeyFilepaths []string
	PreviousRSAPublicKeys   []*rsa.PublicKey

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

	BaseTemplateFilepath            string
	LoginTemplateFilepath           string
	MFACreateTemplateFilepath       string
	MFAVerifyTemplateFilepath       string
	LogoutTemplateFilepath          string
	DeviceTemplateFilepath          string
	ErrorTemplateFilepath           string
	ProfileTemplateFilepath         string
	ProfilePasswordTemplateFilepath string
	ProfileMFATemplateFilepath      string
	SetupTemplateFilepath           string
	ProfilePasskeysTemplateFilepath string
	ResetPasswordTemplateFilepath   string

	// DisablePasskeys disables the login with passkeys (WebAuthn). The passkeys
	// work with an https issuer (or http://localhost), and only in its domain.
	DisablePasskeys bool

	// SetupCode is the code to create the first administrator when the users
	// are in SQLite and there are none. Empty to generate a random one, that is
	// written in the log.
	SetupCode string

	ClientStore      domain.ClientStore
	GrantStore       domain.GrantStore
	SessionStore     domain.SessionStore
	UserStore        domain.UserStore
	UserBlockedStore domain.UserBlockedStore
	MFACodeStore     domain.MFACodeStore
	// PasskeyStore keeps the passkeys (they are stored in SQLite with the MFA)
	PasskeyStore domain.PasskeyStore
	// UserStateStore keeps the state of the accounts (in SQLite if there is a database)
	UserStateStore domain.UserStateStore
	// PasswordResetStore keeps the reset links (in SQLite with the users)
	PasswordResetStore domain.PasswordResetStore
	// GroupStore keeps the descriptions of the groups (in SQLite if there is a database)
	GroupStore domain.GroupStore
	// EventStore keeps the activity log (in SQLite if there is a database)
	EventStore domain.EventStore
	// EventRetention is how long the events are kept (default 90 days)
	EventRetention time.Duration
	// ClientAssertionStore keeps the used jti of the client assertions
	ClientAssertionStore domain.ClientAssertionStore
	DeviceCodeStore      domain.DeviceCodeStore

	sqliteFilepath              string
	sqliteUseInGrants           bool
	sqliteUseInSessions         bool
	sqliteUseInMFA              bool
	sqliteUseInClientAssertions bool
	sqliteUseInUsers            bool
	sqliteUseInClients          bool

	// LDAPServer serves a read only LDAP directory with the users (nil to disable it)
	LDAPServer *domain.LDAPServerConfig

	// AdminEnabled serves the admin web at <issuer>/admin/ to the members of
	// AdminGroup (default "admin"). It requires the clients in SQLite.
	AdminEnabled bool
	AdminGroup   string

	ldap *stores.LDAPConfig

	Clients []Client
	Users   []User
}

type LDAPConfig struct {
	Bind             string
	Password         string
	FilterDN         string
	BaseDN           string
	SubjectAttribute string
	// NameAttribute is the attribute used as preferred_username (the login)
	NameAttribute string
	// optional attributes of the name, given_name and family_name claims
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

type Client struct {
	ID string
	// SecretHash is the bcrypt hash of the secret. Empty for public clients (PKCE is required).
	SecretHash string
	// Secret is the plain secret, only for client_secret_jwt (HMAC assertions)
	Secret                 string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	// TokenEndpointAuthMethod is the only authentication method allowed:
	// client_secret_basic, client_secret_post, client_secret_jwt, private_key_jwt or none.
	// If it is empty, client_secret_basic and client_secret_post are allowed
	// with SecretHash, or none without it.
	TokenEndpointAuthMethod string
	// JWKSURI, PublicKeyPaths (PEM public keys or certificates) and PublicKeys
	// are the keys of the private_key_jwt assertions
	JWKSURI        string
	PublicKeyPaths []string
	PublicKeys     []crypto.PublicKey
	// GrantTypes are the grant types the client can use (default: authorization_code and refresh_token)
	GrantTypes []string
	// AllowedGroups are the groups whose members can use the client (default: all the users)
	AllowedGroups []string
}

type User struct {
	Subject           string
	Email             string
	EmailVerified     bool
	PreferredUsername string
	Name              string
	GivenName         string
	FamilyName        string
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
	b.sqliteUseInClientAssertions = d&ClientAssertions == ClientAssertions
	b.sqliteUseInUsers = d&Users == Users
	b.sqliteUseInClients = d&Clients == Clients

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
	b.ldap = &stores.LDAPConfig{
		Server:               server,
		Bind:                 c.Bind,
		Password:             c.Password,
		FilterDN:             c.FilterDN,
		BaseDN:               c.BaseDN,
		SubjectAttribute:     c.SubjectAttribute,
		NameAttribute:        c.NameAttribute,
		DisplayNameAttribute: c.DisplayNameAttribute,
		GivenNameAttribute:   c.GivenNameAttribute,
		FamilyNameAttribute:  c.FamilyNameAttribute,
		EmailAttribute:       c.EmailAttribute,
		PhoneAttribute:       c.PhoneAttribute,
		AddressAttribute:     c.AddressAttribute,
		GroupsAttribute:      c.GroupsAttribute,
		EmailVerified:        c.EmailVerified,
	}
}

// builds the server
func (b *Builder) Build() (*Minioidc, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}

	if err := b.assignDefaults(); err != nil {
		return nil, err
	}

	if err := b.validateTemplates(); err != nil {
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
	if _, err := issuerBasePath(b.Issuer); err != nil {
		return err
	}
	if b.Audience == "" {
		return errors.New("audience is required")
	}
	if b.MasterKey != "" && len(b.MasterKey) < cryptography.MinMasterKeyLength {
		return fmt.Errorf("masterkey must have at least %d characters", cryptography.MinMasterKeyLength)
	}
	if b.SetupCode != "" && len(b.SetupCode) < minSetupCodeLength {
		return fmt.Errorf("the setup code must have at least %d characters", minSetupCodeLength)
	}
	if b.PrivateRSAKeyFilepath != "" && b.PrivateRSAKey != nil {
		return errors.New("private key and private key filepath are mutually exclusive")
	}
	if b.sqliteFilepath == "" && (b.sqliteUseInGrants || b.sqliteUseInSessions || b.sqliteUseInMFA || b.sqliteUseInClientAssertions || b.sqliteUseInUsers || b.sqliteUseInClients) {
		return errors.New("sqlite filepath is required")
	}
	if b.sqliteUseInGrants && b.DeviceCodeStore != nil {
		return errors.New("sqlite grant store and device code store are mutually exclusive")
	}
	if b.sqliteUseInGrants && b.GrantStore != nil {
		return errors.New("sqlite grant store and grant store are mutually exclusive")
	}
	if b.sqliteUseInSessions && b.SessionStore != nil {
		return errors.New("sqlite session store and session store are mutually exclusive")
	}
	if b.sqliteUseInUsers && (b.UserStore != nil || b.ldap != nil) {
		return errors.New("sqlite user store, ldap and user store are mutually exclusive")
	}
	if b.sqliteUseInClients && b.ClientStore != nil {
		return errors.New("sqlite client store and client store are mutually exclusive")
	}
	if b.LDAPServer != nil {
		if err := b.validateLDAPServer(); err != nil {
			return err
		}
	}
	if b.AdminEnabled && !b.sqliteUseInClients {
		if _, ok := b.ClientStore.(domain.ClientAdminStore); !ok {
			return errors.New("the admin web requires the clients in sqlite (use_in_clients)")
		}
	}
	if b.sqliteUseInMFA && b.PasskeyStore != nil {
		return errors.New("sqlite mfa store and passkey store are mutually exclusive")
	}
	if b.sqliteUseInClientAssertions && b.ClientAssertionStore != nil {
		return errors.New("sqlite client assertion store and client assertion store are mutually exclusive")
	}
	if b.ldap != nil && b.UserStore != nil {
		return errors.New("ldap and user store are mutually exclusive")
	}
	if b.ldap != nil {
		required := map[string]string{
			"bind":              b.ldap.Bind,
			"password":          b.ldap.Password,
			"filter dn":         b.ldap.FilterDN,
			"base dn":           b.ldap.BaseDN,
			"subject attribute": b.ldap.SubjectAttribute,
			"name attribute":    b.ldap.NameAttribute,
			"email attribute":   b.ldap.EmailAttribute,
			"phone attribute":   b.ldap.PhoneAttribute,
			"address attribute": b.ldap.AddressAttribute,
		}
		for name, value := range required {
			if value == "" {
				return fmt.Errorf("ldap %s is required", name)
			}
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
	// defaultEventRetention keeps the activity log for 90 days
	defaultEventRetention = 90 * 24 * time.Hour
	// minSetupCodeLength is the minimum length of a configured setup code
	minSetupCodeLength = 12
)

func (b *Builder) assignDefaults() error {
	if b.Name == "" {
		b.Name = "minioidc"
	}
	if b.MasterKey == "" {
		masterKey, err := cryptography.RandomPassword(cryptography.MinMasterKeyLength)
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
	if b.LDAPServer != nil && b.LDAPServer.Address == "" {
		b.LDAPServer.Address = ":3389"
	}
	if b.AdminGroup == "" {
		b.AdminGroup = "admin"
	}
	if b.EventRetention == 0 {
		b.EventRetention = defaultEventRetention
	}
	if b.LogoutTemplateFilepath == "" {
		b.LogoutTemplateFilepath = "templates/logout.html"
	}
	if b.ErrorTemplateFilepath == "" {
		b.ErrorTemplateFilepath = "templates/error.html"
	}
	if b.DeviceTemplateFilepath == "" {
		b.DeviceTemplateFilepath = "templates/device.html"
	}
	if b.ProfileTemplateFilepath == "" {
		b.ProfileTemplateFilepath = "templates/profile.html"
	}
	if b.ProfilePasswordTemplateFilepath == "" {
		b.ProfilePasswordTemplateFilepath = "templates/profile_password.html"
	}
	if b.ProfileMFATemplateFilepath == "" {
		b.ProfileMFATemplateFilepath = "templates/profile_mfa.html"
	}
	if b.SetupTemplateFilepath == "" {
		b.SetupTemplateFilepath = "templates/setup.html"
	}
	if b.ProfilePasskeysTemplateFilepath == "" {
		b.ProfilePasskeysTemplateFilepath = "templates/profile_passkeys.html"
	}
	if b.ResetPasswordTemplateFilepath == "" {
		b.ResetPasswordTemplateFilepath = "templates/reset_password.html"
	}

	return nil
}

func (b *Builder) config() (*domain.Config, error) {
	basePath, err := issuerBasePath(b.Issuer)
	if err != nil {
		return nil, err
	}

	config := &domain.Config{
		Name:               b.Name,
		ConfigFilepath:     b.ConfigFilepath,
		DataDir:            b.DataDir,
		SqliteFilepath:     b.sqliteFilepath,
		MasterKey:          b.MasterKey,
		Issuer:             b.Issuer,
		BasePath:           basePath,
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

		BaseTemplateFilepath:            b.BaseTemplateFilepath,
		LoginTemplateFilepath:           b.LoginTemplateFilepath,
		MFACreateTemplateFilepath:       b.MFACreateTemplateFilepath,
		MFAVerifyTemplateFilepath:       b.MFAVerifyTemplateFilepath,
		LogoutTemplateFilepath:          b.LogoutTemplateFilepath,
		DeviceTemplateFilepath:          b.DeviceTemplateFilepath,
		ErrorTemplateFilepath:           b.ErrorTemplateFilepath,
		ProfileTemplateFilepath:         b.ProfileTemplateFilepath,
		ProfilePasswordTemplateFilepath: b.ProfilePasswordTemplateFilepath,
		ProfileMFATemplateFilepath:      b.ProfileMFATemplateFilepath,
		SetupTemplateFilepath:           b.SetupTemplateFilepath,
		ProfilePasskeysTemplateFilepath: b.ProfilePasskeysTemplateFilepath,
		ResetPasswordTemplateFilepath:   b.ResetPasswordTemplateFilepath,
		PasskeysEnabled:                 !b.DisablePasskeys,
		SetupCode:                       b.SetupCode,

		AllowImplicitFlow:  b.AllowImplicitFlow,
		AllowPasswordGrant: b.AllowPasswordGrant,

		AdminEnabled:   b.AdminEnabled,
		AdminGroup:     b.AdminGroup,
		EventRetention: b.EventRetention,
		LDAPServer:     b.LDAPServer,
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
	rsaKey := b.PrivateRSAKey
	if b.PrivateRSAKeyFilepath != "" {
		var err error
		rsaKey, err = cryptography.LoadPrivateKey(b.PrivateRSAKeyFilepath)
		if err != nil {
			return fmt.Errorf("load private key: %w", err)
		}
	}

	previous := append([]*rsa.PublicKey{}, b.PreviousRSAPublicKeys...)
	for _, path := range b.PreviousRSAKeyFilepaths {
		publicKey, err := cryptography.LoadPublicKey(path)
		if err != nil {
			return fmt.Errorf("load previous key: %w", err)
		}

		previous = append(previous, publicKey)
	}

	keypair, err := cryptography.NewKeypair(rsaKey, previous...)
	if err != nil {
		return fmt.Errorf("keypair: %w", err)
	}

	config.Keypair = keypair
	return nil
}

func (b *Builder) assignStores(config *domain.Config) error {
	var (
		clientStore      domain.ClientStore
		grantStore       domain.GrantStore
		sessionStore     domain.SessionStore
		userStore        domain.UserStore
		userBlockedStore domain.UserBlockedStore
		mfaStore         domain.MFACodeStore
		sqlite           *sql.DB
		err              error
	)

	if b.sqliteFilepath != "" {
		sqlite, err = db.NewSqliteDB(b.sqliteFilepath)
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
	}

	switch {
	case b.ldap != nil:
		userStore = stores.NewLDAPUserStore(*b.ldap)
	case b.sqliteUseInUsers:
		userStore = stores.NewSqliteUserStore(sqlite)
	case b.UserStore == nil:
		userStore = stores.NewUserStore()
	default:
		userStore = b.UserStore
	}

	switch {
	case b.sqliteUseInClients:
		clientStore = stores.NewSqliteClientStore(sqlite, b.MasterKey)
	case b.ClientStore == nil:
		clientStore = stores.NewClientStore()
	default:
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

	switch {
	case b.UserBlockedStore == nil:
		userBlockedStore = stores.NewUserBlockedStore()
	default:
		userBlockedStore = b.UserBlockedStore
	}

	config.ClientStore = clientStore
	config.GrantStore = grantStore
	config.SessionStore = sessionStore
	config.UserStore = userStore
	config.MFACodeStore = mfaStore

	// the state of the accounts works with any user store: it is kept in the
	// database if there is one
	switch {
	case b.UserStateStore != nil:
		config.UserStateStore = b.UserStateStore
	case sqlite != nil:
		config.UserStateStore = stores.NewSqliteUserStateStore(sqlite)
	default:
		config.UserStateStore = stores.NewUserStateStore()
	}

	switch {
	case b.GroupStore != nil:
		config.GroupStore = b.GroupStore
	case sqlite != nil:
		config.GroupStore = stores.NewSqliteGroupStore(sqlite)
	default:
		config.GroupStore = stores.NewGroupStore()
	}

	switch {
	case b.EventStore != nil:
		config.EventStore = b.EventStore
	case sqlite != nil:
		config.EventStore = stores.NewSqliteEventStore(sqlite)
	default:
		config.EventStore = stores.NewEventStore()
	}

	switch {
	case b.PasswordResetStore != nil:
		config.PasswordResetStore = b.PasswordResetStore
	case b.sqliteUseInUsers:
		config.PasswordResetStore = stores.NewSqlitePasswordResetStore(sqlite)
	default:
		config.PasswordResetStore = stores.NewPasswordResetStore()
	}

	// the passkeys are authenticators, like the MFA codes
	switch {
	case b.sqliteUseInMFA:
		config.PasskeyStore = stores.NewSqlitePasskeyStore(sqlite)
	case b.PasskeyStore == nil:
		config.PasskeyStore = stores.NewPasskeyStore()
	default:
		config.PasskeyStore = b.PasskeyStore
	}
	config.UserBlockedStore = userBlockedStore

	// the device codes are grants: they are stored with the other grants
	switch {
	case b.sqliteUseInGrants:
		config.DeviceCodeStore = stores.NewSqliteDeviceCodeStore(sqlite)
	case b.DeviceCodeStore == nil:
		config.DeviceCodeStore = stores.NewDeviceCodeStore()
	default:
		config.DeviceCodeStore = b.DeviceCodeStore
	}

	switch {
	case b.sqliteUseInClientAssertions:
		config.ClientAssertionStore = stores.NewSqliteClientAssertionStore(sqlite)
	case b.ClientAssertionStore == nil:
		config.ClientAssertionStore = stores.NewClientAssertionStore()
	default:
		config.ClientAssertionStore = b.ClientAssertionStore
	}

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

// seedClients adds the clients of the configuration that do not exist, so the
// changes made in the admin web to the clients stored in SQLite are kept
func (b *Builder) seedClients(clientStore domain.ClientStore) error {
	for _, c := range b.Clients {
		if _, err := clientStore.GetClientByID(c.ID); err == nil {
			continue
		}

		publicKeys := append([]crypto.PublicKey{}, c.PublicKeys...)
		for _, path := range c.PublicKeyPaths {
			key, err := cryptography.LoadAnyPublicKey(path)
			if err != nil {
				return fmt.Errorf("seed clients: %w", err)
			}

			publicKeys = append(publicKeys, key)
		}

		_, err := clientStore.NewClient(domain.ClientData{
			ID:                      c.ID,
			SecretHash:              c.SecretHash,
			Secret:                  c.Secret,
			RedirectURIs:            c.RedirectURIs,
			PostLogoutRedirectURIs:  c.PostLogoutRedirectURIs,
			TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
			JWKSURI:                 c.JWKSURI,
			PublicKeys:              publicKeys,
			GrantTypes:              c.GrantTypes,
			AllowedGroups:           c.AllowedGroups,
		})
		if err != nil {
			return fmt.Errorf("seed clients: %w", err)
		}
	}

	return nil
}

// seedUsers adds the users of the configuration that do not exist, so the
// changes made in the admin web to the users stored in SQLite are kept
func (b *Builder) seedUsers(userStore domain.UserStore) error {
	for _, u := range b.Users {
		if _, err := userStore.GetUserByID(u.Subject); err == nil {
			continue
		}

		_, err := userStore.NewUser(domain.UserData{
			Subject:           u.Subject,
			Email:             u.Email,
			EmailVerified:     u.EmailVerified,
			PreferredUsername: u.PreferredUsername,
			Name:              u.Name,
			GivenName:         u.GivenName,
			FamilyName:        u.FamilyName,
			Phone:             u.Phone,
			Address:           u.Address,
			Groups:            u.Groups,
			PasswordHash:      u.PasswordHash,
		})
		if err != nil {
			return fmt.Errorf("seed users: %w", err)
		}
	}

	return nil
}

// issuerBasePath validates the issuer (OIDC Discovery section 3: an URL with
// scheme and host, without query or fragment) and returns its path without
// trailing slash, where the endpoints are published.
func issuerBasePath(issuer string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("issuer must be an http(s) URL without query or fragment: %s", issuer)
	}

	return strings.TrimSuffix(u.Path, "/"), nil
}

func (b *Builder) validateLDAPServer() error {
	c := b.LDAPServer
	switch {
	case c.BaseDN == "":
		return errors.New("ldap server: base_dn is required")
	case b.ldap != nil:
		return errors.New("ldap server: it cannot serve the users of another LDAP server")
	case c.BindDN != "" && c.BindPasswordHash == "":
		return errors.New("ldap server: bind_password_hash is required with bind_dn")
	case c.TLSMode != domain.LDAPTLSNone && (c.TLSCertPath == "" || c.TLSKeyPath == ""):
		return errors.New("ldap server: the tls cert_path and key_path are required")
	}

	switch c.TLSMode {
	case domain.LDAPTLSNone, domain.LDAPTLSLDAPS, domain.LDAPTLSStartTLS:
		return nil
	default:
		return fmt.Errorf("ldap server: unsupported tls mode %q (use ldaps or starttls)", c.TLSMode)
	}
}

// validateTemplates checks that the template files exist, so a wrong path or
// working directory fails with a clear error on start up
func (b *Builder) validateTemplates() error {
	for _, path := range []string{
		b.BaseTemplateFilepath, b.LoginTemplateFilepath, b.MFACreateTemplateFilepath, b.MFAVerifyTemplateFilepath, b.LogoutTemplateFilepath,
		b.DeviceTemplateFilepath, b.ErrorTemplateFilepath, b.ProfileTemplateFilepath, b.ProfilePasswordTemplateFilepath, b.ProfileMFATemplateFilepath,
		b.SetupTemplateFilepath, b.ProfilePasskeysTemplateFilepath, b.ResetPasswordTemplateFilepath,
	} {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("template not found: %s (the paths are relative to the working directory)", path)
		}
	}

	return nil
}

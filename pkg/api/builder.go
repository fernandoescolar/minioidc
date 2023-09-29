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
	NoSqliteDatabases SqliteDatabases = iota
	OnlyInGrants
	OnlyInSessions
	InGrantsAndSessions
)

type Builder struct {
	Name                  string
	MasterKey             string
	Issuer                string
	Audience              string
	PrivateRSAKeyFilepath string
	PrivateRSAKey         *rsa.PrivateKey

	AccessTTL  time.Duration
	RefreshTTL time.Duration
	SessionTTL time.Duration
	CodeTTL    time.Duration

	LoginTemplateFilepath string

	ClientStore  domain.ClientStore
	GrantStore   domain.GrantStore
	SessionStore domain.SessionStore
	UserStore    domain.UserStore

	sqliteFilepath      string
	sqliteUseInGrants   bool
	sqliteUseInSessions bool

	Clients []Client
	Users   []User
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

	switch d {
	case OnlyInGrants:
		b.sqliteUseInGrants = true
		b.sqliteUseInSessions = false
	case OnlyInSessions:
		b.sqliteUseInGrants = false
		b.sqliteUseInSessions = true
	case InGrantsAndSessions:
		b.sqliteUseInGrants = true
		b.sqliteUseInSessions = true
	default:
		b.sqliteUseInGrants = false
		b.sqliteUseInSessions = false
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

	return nil
}

const (
	defaultAccessTTL  = 20
	defaultRefreshTTL = 129600
	defaultSessionTTL = 129600
	defaultCodeTTL    = 5
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
	if b.LoginTemplateFilepath == "" {
		b.LoginTemplateFilepath = "templates/login1.html"
	}

	return nil
}

func (b *Builder) config() (*domain.Config, error) {
	config := &domain.Config{
		Name:      b.Name,
		MasterKey: b.MasterKey,
		Issuer:    b.Issuer,
		Audience:  b.Audience,

		AccessTTL:  b.AccessTTL,
		RefreshTTL: b.RefreshTTL,
		SessionTTL: b.SessionTTL,
		CodeTTL:    b.CodeTTL,

		LoginTemplateFilepath: b.LoginTemplateFilepath,
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
		sqlite       *sql.DB
		err          error
	)

	if b.sqliteFilepath != "" {
		sqlite, err = db.NewSqliteDB(b.sqliteFilepath)
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
	}

	if b.UserStore == nil {
		userStore = stores.NewUserStore()
	} else {
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

	config.ClientStore = clientStore
	config.GrantStore = grantStore
	config.SessionStore = sessionStore
	config.UserStore = userStore

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

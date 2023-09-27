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
	issuer                string
	audience              string
	privateRSAKeyFilepath string
	privateRSAKey         *rsa.PrivateKey

	accessTTL  time.Duration
	refreshTTL time.Duration
	sessionTTL time.Duration
	codeTTL    time.Duration

	loginTemplateFilepath string

	clientStore  domain.ClientStore
	grantStore   domain.GrantStore
	sessionStore domain.SessionStore
	userStore    domain.UserStore

	sqliteFilepath      string
	sqliteUseInGrants   bool
	sqliteUseInSessions bool

	clients []Client
	users   []User
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

func NewBuilder() *Builder {
	return &Builder{}
}

func (b *Builder) WithIssuer(i string) *Builder {
	b.issuer = i
	return b
}

func (b *Builder) WithAudience(a string) *Builder {
	b.audience = a
	return b
}

func (b *Builder) WithPrivateKey(k *rsa.PrivateKey) *Builder {
	b.privateRSAKey = k
	return b
}

func (b *Builder) WithPrivateKeyFile(f string) *Builder {
	b.privateRSAKeyFilepath = f
	return b
}

func (b *Builder) WithAccessTTL(t time.Duration) *Builder {
	b.accessTTL = t
	return b
}

func (b *Builder) WithRefreshTTL(t time.Duration) *Builder {
	b.refreshTTL = t
	return b
}

func (b *Builder) WithSessionTTL(t time.Duration) *Builder {
	b.sessionTTL = t
	return b
}

func (b *Builder) WithCodeTTL(t time.Duration) *Builder {
	b.codeTTL = t
	return b
}

func (b *Builder) WithClientStore(c domain.ClientStore) *Builder {
	b.clientStore = c
	return b
}

func (b *Builder) WithGrantStore(g domain.GrantStore) *Builder {
	b.grantStore = g
	return b
}

func (b *Builder) WithSessionStore(s domain.SessionStore) *Builder {
	b.sessionStore = s
	return b
}

func (b *Builder) WithUserStore(u domain.UserStore) *Builder {
	b.userStore = u
	return b
}

func (b *Builder) WithLoginTemplate(l string) *Builder {
	b.loginTemplateFilepath = l
	return b
}

func (b *Builder) WithSQLite(f string, d SqliteDatabases) *Builder {
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

	return b
}

func (b *Builder) WithClients(c []Client) *Builder {
	b.clients = c
	return b
}

func (b *Builder) WithUsers(u []User) *Builder {
	b.users = u
	return b
}

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

	return NewMinioidc(config)
}

func (b *Builder) validate() error {
	if b.issuer == "" {
		return errors.New("issuer is required")
	}
	if b.audience == "" {
		return errors.New("audience is required")
	}
	if b.privateRSAKeyFilepath != "" && b.privateRSAKey != nil {
		return errors.New("private key and private key filepath are mutually exclusive")
	}
	if b.sqliteFilepath == "" && (b.sqliteUseInGrants || b.sqliteUseInSessions) {
		return errors.New("sqlite filepath is required")
	}
	if b.sqliteUseInGrants && b.grantStore != nil {
		return errors.New("sqlite grant store and grant store are mutually exclusive")
	}
	if b.sqliteUseInSessions && b.sessionStore != nil {
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
	if b.privateRSAKeyFilepath == "" && b.privateRSAKey == nil {
		rk, err := rsa.GenerateKey(rand.Reader, defaultRSASize)
		if err != nil {
			return fmt.Errorf("random keypair: %w", err)
		}

		b.privateRSAKey = rk
	}
	if b.accessTTL == 0 {
		b.accessTTL = defaultAccessTTL * time.Minute
	}
	if b.refreshTTL == 0 {
		b.refreshTTL = defaultRefreshTTL * time.Minute
	}
	if b.sessionTTL == 0 {
		b.sessionTTL = defaultSessionTTL * time.Minute
	}
	if b.codeTTL == 0 {
		b.codeTTL = defaultCodeTTL * time.Minute
	}
	if b.loginTemplateFilepath == "" {
		b.loginTemplateFilepath = "templates/login1.html"
	}

	return nil
}

func (b *Builder) config() (*domain.Config, error) {
	config := &domain.Config{
		Issuer:   b.issuer,
		Audience: b.audience,

		AccessTTL:  b.accessTTL,
		RefreshTTL: b.refreshTTL,
		SessionTTL: b.sessionTTL,
		CodeTTL:    b.codeTTL,

		LoginTemplateFilepath: b.loginTemplateFilepath,
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
	if b.privateRSAKey != nil {
		keypair, err := cryptography.NewKeypair(b.privateRSAKey)
		if err != nil {
			return fmt.Errorf("keypair: %w", err)
		}

		config.Keypair = keypair
	}

	if b.privateRSAKeyFilepath != "" {
		rsaKey, err := cryptography.LoadPrivateKey(b.privateRSAKeyFilepath)
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

	if b.userStore == nil {
		userStore = stores.NewUserStore()
	} else {
		userStore = b.userStore
	}

	if b.clientStore == nil {
		clientStore = stores.NewClientStore()
	} else {
		clientStore = b.clientStore
	}

	switch {
	case b.sqliteUseInSessions:
		sessionStore = stores.NewSqliteSessionStore(sqlite, userStore)
	case b.sessionStore == nil:
		sessionStore = stores.NewSessionStore(userStore)
	default:
		sessionStore = b.sessionStore
	}

	switch {
	case b.sqliteUseInGrants:
		grantStore = stores.NewSqliteGrantStore(sqlite, clientStore, sessionStore)
	case b.grantStore == nil:
		grantStore = stores.NewGrantStore(clientStore, sessionStore)
	default:
		grantStore = b.grantStore
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
	for _, c := range b.clients {
		_, err := clientStore.NewClient(c.ID, c.SecretHash, c.RedirectURIs)
		if err != nil {
			return fmt.Errorf("seed clients: %w", err)
		}
	}

	return nil
}

func (b *Builder) seedUsers(userStore domain.UserStore) error {
	for _, u := range b.users {
		_, err := userStore.NewUser(u.Subject, u.Email, u.PreferredUsername, u.Phone, u.Address, u.Groups, u.PasswordHash)
		if err != nil {
			return fmt.Errorf("seed users: %w", err)
		}
	}

	return nil
}

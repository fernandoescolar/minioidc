package builder

import (
	"crypto/rsa"
	"log"
	"os"
	"time"

	"github.com/fernandoescolar/minioidc/internal/db"
	"github.com/fernandoescolar/minioidc/internal/stores"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
	"gopkg.in/yaml.v3"
)

type yamlBuilder struct {
	internalConfig *YamlConfig
}

type YamlConfig struct {
	Server struct {
		Issuer            string `yaml:"issuer"`
		Audience          string `yaml:"audience"`
		PrivateRSAKeyPath string `yaml:"private_rsa_key_path"`

		AccessTTL  int `yaml:"access_ttl"`
		RefreshTTL int `yaml:"refresh_ttl"`
		SessionTTL int `yaml:"session_ttl"`
		CodeTTL    int `yaml:"code_ttl"`

		SqliteFilepath        string `yaml:"sqlite_filepath"`
		UseSqliteGrantStore   bool   `yaml:"use_sqlite_grant_store"`
		UseSqliteSessionStore bool   `yaml:"use_sqlite_session_store"`
	} `yaml:"server"`
	Templates struct {
		Login string `yaml:"login"`
	} `yaml:"templates"`
	Clients []struct {
		ID           string   `yaml:"id"`
		SecretHash   string   `yaml:"secret_hash"`
		RedirectURIs []string `yaml:"redirect_uris"`
	} `yaml:"clients"`
	Users []struct {
		Subject           string   `yaml:"subject"`
		Email             string   `yaml:"email"`
		EmailVerified     bool     `yaml:"email_verified"`
		PreferredUsername string   `yaml:"preferred_username"`
		PasswordHash      string   `yaml:"password_hash"`
		Phone             string   `yaml:"phone"`
		Address           string   `yaml:"address"`
		Groups            []string `yaml:"groups"`
	} `yaml:"users"`
}

func NewYamlBuilder(filepath string) IBuilder {
	yamlConfig := &YamlConfig{}
	yfile, err := os.ReadFile(filepath)
	if err != nil {
		log.Fatal(err)
	}

	err = yaml.Unmarshal(yfile, yamlConfig)
	if err != nil {
		log.Fatal(err)
	}

	return &yamlBuilder{
		internalConfig: yamlConfig,
	}
}

func (y *yamlBuilder) Build() *domain.Config {
	keypair, err := y.internalConfig.GetKeypair()
	if err != nil {
		log.Fatal(err)
	}

	db, err := db.NewSqliteDB(y.internalConfig.Server.SqliteFilepath)
	if err != nil {
		log.Fatal(err)
	}

	var (
		sessionStore domain.SessionStore
		grantStore   domain.GrantStore
	)

	clientStore := stores.NewClientStore()
	userStore := stores.NewUserStore()

	if y.internalConfig.Server.UseSqliteSessionStore {
		sessionStore = stores.NewSqliteSessionStore(db, userStore)
	} else {
		sessionStore = stores.NewSessionStore(userStore)
	}

	if y.internalConfig.Server.UseSqliteGrantStore {
		grantStore = stores.NewSqliteGrantStore(db, clientStore, sessionStore)
	} else {
		grantStore = stores.NewGrantStore(clientStore, sessionStore)
	}

	y.internalConfig.addClients(clientStore)
	y.internalConfig.addUsers(userStore)

	loginTemplateFilepath := y.internalConfig.Templates.Login
	if loginTemplateFilepath == "" {
		loginTemplateFilepath = "templates/login1.html"
	}

	accessTTL := y.internalConfig.Server.AccessTTL
	if accessTTL == 0 {
		accessTTL = 20
	}

	refreshTTL := y.internalConfig.Server.RefreshTTL
	if refreshTTL == 0 {
		refreshTTL = 129600
	}

	sessionTTL := y.internalConfig.Server.SessionTTL
	if sessionTTL == 0 {
		sessionTTL = 129600
	}

	codeTTL := y.internalConfig.Server.CodeTTL
	if codeTTL == 0 {
		codeTTL = 5
	}

	return &domain.Config{
		Issuer:   y.internalConfig.Server.Issuer,
		Audience: y.internalConfig.Server.Audience,
		Keypair:  keypair,

		AccessTTL:  time.Duration(y.internalConfig.Server.AccessTTL) * time.Minute,
		RefreshTTL: time.Duration(y.internalConfig.Server.RefreshTTL) * time.Minute,
		SessionTTL: time.Duration(y.internalConfig.Server.SessionTTL) * time.Minute,
		CodeTTL:    time.Duration(y.internalConfig.Server.CodeTTL) * time.Minute,

		ClientStore:  clientStore,
		GrantStore:   grantStore,
		SessionStore: sessionStore,
		UserStore:    userStore,

		LoginTemplateFilepath: loginTemplateFilepath,
	}
}

func (y *YamlConfig) GetKeypair() (*cryptography.Keypair, error) {
	if y.Server.PrivateRSAKeyPath == "" {
		return cryptography.RandomKeypair(1024)
	}

	rsaKey, err := y.rsaPrivateKey()
	if err != nil {
		return nil, err
	}

	keypair, err := cryptography.NewKeypair(rsaKey)
	if err != nil {
		return nil, err
	}

	return keypair, nil
}

func (y *YamlConfig) rsaPrivateKey() (*rsa.PrivateKey, error) {
	rsaKey, err := cryptography.LoadPrivateKey(y.Server.PrivateRSAKeyPath)
	if err != nil {
		return nil, err
	}

	return rsaKey, nil
}

func (y *YamlConfig) addClients(store domain.ClientStore) {
	for _, c := range y.Clients {
		store.NewClient(c.ID, c.SecretHash, c.RedirectURIs)
	}
}

func (y *YamlConfig) addUsers(store domain.UserStore) {
	for _, u := range y.Users {
		store.NewUser(u.Subject, u.Email, u.PreferredUsername, u.Phone, u.Address, u.Groups, u.PasswordHash)
	}
}

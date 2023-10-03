package api

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type YamlConfig struct {
	Name      string `yaml:"name"`
	MasterKey string `yaml:"masterkey"`

	Issuer             string `yaml:"issuer"`
	Audience           string `yaml:"audience"`
	RequireMFA         bool   `yaml:"require_mfa"`
	ReuseRefreshTokens bool   `yaml:"reuse_refresh_tokens"`
	PrivateRSAKeyPath  string `yaml:"private_rsa_key_path"`

	Middlewares struct {
		HSTS           bool `yaml:"hsts"`
		CSP            bool `yaml:"csp"`
		SecureCookies  bool `yaml:"secure_cookies"`
		ForwardHeaders bool `yaml:"forward_headers"`
		LogRequests    bool `yaml:"log_requests"`
	} `yaml:"middlewares"`

	TTL struct {
		Access  int `yaml:"access"`
		Refresh int `yaml:"refresh"`
		Session int `yaml:"session"`
		Code    int `yaml:"code"`
	} `yaml:"ttl"`

	Templates struct {
		Base      string `yaml:"base"`
		Login     string `yaml:"login"`
		MFACreate string `yaml:"mfa_create"`
		MFAVerify string `yaml:"mfa_verify"`
	} `yaml:"templates"`

	Sqlite struct {
		Filepath      string `yaml:"filepath"`
		UseInGrants   bool   `yaml:"use_in_grants"`
		UseInSessions bool   `yaml:"use_in_sessions"`
		UseInMFA      bool   `yaml:"use_in_mfa"`
	} `yaml:"sqlite"`

	Clients []struct {
		ID           string   `yaml:"id"`
		SecretHash   string   `yaml:"secret_hash"`
		RedirectURIs []string `yaml:"redirect_uris"`
	} `yaml:"clients"`

	Users []struct {
		Subject           string   `yaml:"subject"`
		Email             string   `yaml:"email"`
		PreferredUsername string   `yaml:"preferred_username"`
		PasswordHash      string   `yaml:"password_hash"`
		Phone             string   `yaml:"phone"`
		Address           string   `yaml:"address"`
		Groups            []string `yaml:"groups"`
	} `yaml:"users"`
}

func NewYamlBuilder(filepath string) (*Builder, error) {
	yamlConfig := &YamlConfig{}
	yfile, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("Build: %w", err)
	}

	if err = yaml.Unmarshal(yfile, yamlConfig); err != nil {
		return nil, fmt.Errorf("Build: %w", err)
	}

	sqliteDatabases := NoSqliteDatabases
	if yamlConfig.Sqlite.UseInGrants {
		sqliteDatabases = sqliteDatabases | Grants
	}
	if yamlConfig.Sqlite.UseInSessions {
		sqliteDatabases = sqliteDatabases | Sessions
	}
	if yamlConfig.Sqlite.UseInMFA {
		sqliteDatabases = sqliteDatabases | MFA
	}

	clients := make([]Client, len(yamlConfig.Clients))
	for i, c := range yamlConfig.Clients {
		clients[i] = Client{
			ID:           c.ID,
			SecretHash:   c.SecretHash,
			RedirectURIs: c.RedirectURIs,
		}
	}

	users := make([]User, len(yamlConfig.Users))
	for i, yuser := range yamlConfig.Users {
		users[i] = User{
			Subject:           yuser.Subject,
			Email:             yuser.Email,
			PreferredUsername: yuser.PreferredUsername,
			PasswordHash:      yuser.PasswordHash,
			Phone:             yuser.Phone,
			Address:           yuser.Address,
			Groups:            yuser.Groups,
		}
	}

	builder := &Builder{
		Name:                  yamlConfig.Name,
		MasterKey:             yamlConfig.MasterKey,
		Issuer:                yamlConfig.Issuer,
		Audience:              yamlConfig.Audience,
		RequireMFA:            yamlConfig.RequireMFA,
		ReuseRefreshTokens:    yamlConfig.ReuseRefreshTokens,
		PrivateRSAKeyFilepath: yamlConfig.PrivateRSAKeyPath,

		UseHSTS:             yamlConfig.Middlewares.HSTS,
		UseCSP:              yamlConfig.Middlewares.CSP,
		UseSecureCookie:     yamlConfig.Middlewares.SecureCookies,
		UseForwardedHeaders: yamlConfig.Middlewares.ForwardHeaders,
		LogRequests:         yamlConfig.Middlewares.LogRequests,

		BaseTemplateFilepath:      yamlConfig.Templates.Base,
		LoginTemplateFilepath:     yamlConfig.Templates.Login,
		MFACreateTemplateFilepath: yamlConfig.Templates.MFACreate,
		MFAVerifyTemplateFilepath: yamlConfig.Templates.MFAVerify,

		AccessTTL:  time.Duration(yamlConfig.TTL.Access) * time.Minute,
		RefreshTTL: time.Duration(yamlConfig.TTL.Refresh) * time.Minute,
		SessionTTL: time.Duration(yamlConfig.TTL.Session) * time.Minute,
		CodeTTL:    time.Duration(yamlConfig.TTL.Code) * time.Minute,

		Clients: clients,
		Users:   users,
	}

	builder.UseSQLite(yamlConfig.Sqlite.Filepath, sqliteDatabases)
	return builder, nil
}

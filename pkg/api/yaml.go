package api

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type YamlConfig struct {
	Issuer            string `yaml:"issuer"`
	Audience          string `yaml:"audience"`
	PrivateRSAKeyPath string `yaml:"private_rsa_key_path"`

	TTL struct {
		Access  int `yaml:"access"`
		Refresh int `yaml:"refresh"`
		Session int `yaml:"session"`
		Code    int `yaml:"code"`
	} `yaml:"ttl"`

	Templates struct {
		Login string `yaml:"login"`
	} `yaml:"templates"`

	Sqlite struct {
		Filepath      string `yaml:"filepath"`
		UseInGrants   bool   `yaml:"use_in_grants"`
		UseInSessions bool   `yaml:"use_in_sessions"`
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
	switch {
	case yamlConfig.Sqlite.UseInGrants && yamlConfig.Sqlite.UseInSessions:
		sqliteDatabases = InGrantsAndSessions
	case yamlConfig.Sqlite.UseInGrants:
		sqliteDatabases = OnlyInGrants
	case yamlConfig.Sqlite.UseInSessions:
		sqliteDatabases = OnlyInSessions
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

	return NewBuilder().
		WithIssuer(yamlConfig.Issuer).
		WithAudience(yamlConfig.Audience).
		WithPrivateKeyFile(yamlConfig.PrivateRSAKeyPath).
		WithLoginTemplate(yamlConfig.Templates.Login).
		WithAccessTTL(time.Duration(yamlConfig.TTL.Access)*time.Minute).
		WithRefreshTTL(time.Duration(yamlConfig.TTL.Refresh)*time.Minute).
		WithSessionTTL(time.Duration(yamlConfig.TTL.Session)*time.Minute).
		WithCodeTTL(time.Duration(yamlConfig.TTL.Code)*time.Minute).
		WithSQLite(yamlConfig.Sqlite.Filepath, sqliteDatabases).
		WithClients(clients).
		WithUsers(users), nil
}

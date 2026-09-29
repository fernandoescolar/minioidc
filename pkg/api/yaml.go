package api

import (
	"fmt"
	"github.com/fernandoescolar/minioidc/pkg/domain"
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
	// previous signing keys, still published in the JWKS during a key rotation
	PreviousRSAKeyPaths []string `yaml:"previous_rsa_key_paths"`

	// the discouraged flows (RFC 9700), disabled by default
	Grants struct {
		Implicit bool `yaml:"implicit"`
		Password bool `yaml:"password"`
	} `yaml:"grants"`

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
		CSRF    int `yaml:"csrf"`
	} `yaml:"ttl"`

	Templates struct {
		Base            string `yaml:"base"`
		Login           string `yaml:"login"`
		MFACreate       string `yaml:"mfa_create"`
		MFAVerify       string `yaml:"mfa_verify"`
		Logout          string `yaml:"logout"`
		Device          string `yaml:"device"`
		Error           string `yaml:"error"`
		Profile         string `yaml:"profile"`
		ProfilePassword string `yaml:"profile_password"`
		ProfileMFA      string `yaml:"profile_mfa"`
		Setup           string `yaml:"setup"`
	} `yaml:"templates"`

	Sqlite struct {
		Filepath              string `yaml:"filepath"`
		UseInGrants           bool   `yaml:"use_in_grants"`
		UseInSessions         bool   `yaml:"use_in_sessions"`
		UseInMFA              bool   `yaml:"use_in_mfa"`
		UseInClientAssertions bool   `yaml:"use_in_client_assertions"`
		UseInUsers            bool   `yaml:"use_in_users"`
		UseInClients          bool   `yaml:"use_in_clients"`
	} `yaml:"sqlite"`
	LDAPServer struct {
		Enabled          bool   `yaml:"enabled"`
		Address          string `yaml:"address"`
		BaseDN           string `yaml:"base_dn"`
		BindDN           string `yaml:"bind_dn"`
		BindPasswordHash string `yaml:"bind_password_hash"`
		AllowAnonymous   bool   `yaml:"allow_anonymous"`
		UsersCanSearch   bool   `yaml:"users_can_search"`
		TLS              struct {
			Mode     string `yaml:"mode"`
			CertPath string `yaml:"cert_path"`
			KeyPath  string `yaml:"key_path"`
		} `yaml:"tls"`
	} `yaml:"ldap_server"`

	Admin struct {
		Enabled bool   `yaml:"enabled"`
		Group   string `yaml:"group"`
	} `yaml:"admin"`

	Ldap struct {
		Server        string `yaml:"server"`
		Bind          string `yaml:"bind"`
		Password      string `yaml:"password"`
		BaseDN        string `yaml:"base_dn"`
		FilterDN      string `yaml:"filter_dn"`
		EmailVerified bool   `yaml:"email_verified"`
		Attributes    struct {
			Subject     string `yaml:"subject"`
			Name        string `yaml:"name"`
			DisplayName string `yaml:"display_name"`
			GivenName   string `yaml:"given_name"`
			FamilyName  string `yaml:"family_name"`
			Email       string `yaml:"email"`
			Phone       string `yaml:"phone"`
			Address     string `yaml:"address"`
			Groups      string `yaml:"groups"`
		} `yaml:"attributes"`
	} `yaml:"ldap"`
	Clients []struct {
		ID                      string   `yaml:"id"`
		SecretHash              string   `yaml:"secret_hash"`
		RedirectURIs            []string `yaml:"redirect_uris"`
		PostLogoutRedirectURIs  []string `yaml:"post_logout_redirect_uris"`
		TokenEndpointAuthMethod string   `yaml:"token_endpoint_auth_method"`
		Secret                  string   `yaml:"secret"`
		JWKSURI                 string   `yaml:"jwks_uri"`
		PublicKeyPaths          []string `yaml:"public_key_paths"`
		GrantTypes              []string `yaml:"grant_types"`
	} `yaml:"clients"`

	Users []struct {
		Subject           string   `yaml:"subject"`
		Email             string   `yaml:"email"`
		EmailVerified     bool     `yaml:"email_verified"`
		PreferredUsername string   `yaml:"preferred_username"`
		Name              string   `yaml:"name"`
		GivenName         string   `yaml:"given_name"`
		FamilyName        string   `yaml:"family_name"`
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

	// load environment variables
	ystring := os.Expand(string(yfile), func(key string) string {
		v := os.Getenv(key)
		if v == "" {
			return "$" + key
		}

		return v
	})

	yfile = []byte(ystring)
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
	if yamlConfig.Sqlite.UseInClientAssertions {
		sqliteDatabases = sqliteDatabases | ClientAssertions
	}
	if yamlConfig.Sqlite.UseInUsers {
		sqliteDatabases = sqliteDatabases | Users
	}
	if yamlConfig.Sqlite.UseInClients {
		sqliteDatabases = sqliteDatabases | Clients
	}

	clients := make([]Client, len(yamlConfig.Clients))
	for i, c := range yamlConfig.Clients {
		clients[i] = Client{
			ID:                      c.ID,
			SecretHash:              c.SecretHash,
			RedirectURIs:            c.RedirectURIs,
			PostLogoutRedirectURIs:  c.PostLogoutRedirectURIs,
			TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
			Secret:                  c.Secret,
			JWKSURI:                 c.JWKSURI,
			PublicKeyPaths:          c.PublicKeyPaths,
			GrantTypes:              c.GrantTypes,
		}
	}

	users := make([]User, len(yamlConfig.Users))
	for i, yuser := range yamlConfig.Users {
		users[i] = User{
			Subject:           yuser.Subject,
			Email:             yuser.Email,
			EmailVerified:     yuser.EmailVerified,
			PreferredUsername: yuser.PreferredUsername,
			Name:              yuser.Name,
			GivenName:         yuser.GivenName,
			FamilyName:        yuser.FamilyName,
			PasswordHash:      yuser.PasswordHash,
			Phone:             yuser.Phone,
			Address:           yuser.Address,
			Groups:            yuser.Groups,
		}
	}

	builder := &Builder{
		Name:                    yamlConfig.Name,
		MasterKey:               yamlConfig.MasterKey,
		Issuer:                  yamlConfig.Issuer,
		Audience:                yamlConfig.Audience,
		RequireMFA:              yamlConfig.RequireMFA,
		ReuseRefreshTokens:      yamlConfig.ReuseRefreshTokens,
		PrivateRSAKeyFilepath:   yamlConfig.PrivateRSAKeyPath,
		PreviousRSAKeyFilepaths: yamlConfig.PreviousRSAKeyPaths,

		UseHSTS:             yamlConfig.Middlewares.HSTS,
		UseCSP:              yamlConfig.Middlewares.CSP,
		UseSecureCookie:     yamlConfig.Middlewares.SecureCookies,
		UseForwardedHeaders: yamlConfig.Middlewares.ForwardHeaders,
		AdminEnabled:        yamlConfig.Admin.Enabled,
		AdminGroup:          yamlConfig.Admin.Group,
		LogRequests:         yamlConfig.Middlewares.LogRequests,

		BaseTemplateFilepath:            yamlConfig.Templates.Base,
		LoginTemplateFilepath:           yamlConfig.Templates.Login,
		MFACreateTemplateFilepath:       yamlConfig.Templates.MFACreate,
		MFAVerifyTemplateFilepath:       yamlConfig.Templates.MFAVerify,
		LogoutTemplateFilepath:          yamlConfig.Templates.Logout,
		DeviceTemplateFilepath:          yamlConfig.Templates.Device,
		ErrorTemplateFilepath:           yamlConfig.Templates.Error,
		ProfileTemplateFilepath:         yamlConfig.Templates.Profile,
		ProfilePasswordTemplateFilepath: yamlConfig.Templates.ProfilePassword,
		ProfileMFATemplateFilepath:      yamlConfig.Templates.ProfileMFA,
		SetupTemplateFilepath:           yamlConfig.Templates.Setup,
		AllowImplicitFlow:               yamlConfig.Grants.Implicit,
		AllowPasswordGrant:              yamlConfig.Grants.Password,

		AccessTTL:  time.Duration(yamlConfig.TTL.Access) * time.Minute,
		RefreshTTL: time.Duration(yamlConfig.TTL.Refresh) * time.Minute,
		SessionTTL: time.Duration(yamlConfig.TTL.Session) * time.Minute,
		CodeTTL:    time.Duration(yamlConfig.TTL.Code) * time.Minute,
		CSRFTTL:    time.Duration(yamlConfig.TTL.CSRF) * time.Minute,

		Clients: clients,
		Users:   users,
	}

	if yamlConfig.LDAPServer.Enabled {
		builder.LDAPServer = &domain.LDAPServerConfig{
			Address:          yamlConfig.LDAPServer.Address,
			BaseDN:           yamlConfig.LDAPServer.BaseDN,
			BindDN:           yamlConfig.LDAPServer.BindDN,
			BindPasswordHash: yamlConfig.LDAPServer.BindPasswordHash,
			AllowAnonymous:   yamlConfig.LDAPServer.AllowAnonymous,
			UsersCanSearch:   yamlConfig.LDAPServer.UsersCanSearch,
			TLSMode:          yamlConfig.LDAPServer.TLS.Mode,
			TLSCertPath:      yamlConfig.LDAPServer.TLS.CertPath,
			TLSKeyPath:       yamlConfig.LDAPServer.TLS.KeyPath,
		}
	}

	builder.UseSQLite(yamlConfig.Sqlite.Filepath, sqliteDatabases)
	if yamlConfig.Ldap.Server != "" {
		builder.UseLDAP(
			yamlConfig.Ldap.Server,
			LDAPConfig{
				Bind:                 yamlConfig.Ldap.Bind,
				Password:             yamlConfig.Ldap.Password,
				FilterDN:             yamlConfig.Ldap.FilterDN,
				BaseDN:               yamlConfig.Ldap.BaseDN,
				SubjectAttribute:     yamlConfig.Ldap.Attributes.Subject,
				NameAttribute:        yamlConfig.Ldap.Attributes.Name,
				DisplayNameAttribute: yamlConfig.Ldap.Attributes.DisplayName,
				GivenNameAttribute:   yamlConfig.Ldap.Attributes.GivenName,
				FamilyNameAttribute:  yamlConfig.Ldap.Attributes.FamilyName,
				EmailVerified:        yamlConfig.Ldap.EmailVerified,
				GroupsAttribute:      yamlConfig.Ldap.Attributes.Groups,
				EmailAttribute:       yamlConfig.Ldap.Attributes.Email,
				PhoneAttribute:       yamlConfig.Ldap.Attributes.Phone,
				AddressAttribute:     yamlConfig.Ldap.Attributes.Address,
			})
	}
	return builder, nil
}

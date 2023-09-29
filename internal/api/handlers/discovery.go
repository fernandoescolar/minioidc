package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
)

var (
	GrantTypesSupported = []string{
		"authorization_code",
		"refresh_token",
	}
	ResponseTypesSupported = []string{
		"code",
	}
	SubjectTypesSupported = []string{
		"public",
	}
	IDTokenSigningAlgValuesSupported = []string{
		"RS256",
	}
	ScopesSupported = []string{
		"openid",
		"email",
		"groups",
		"profile",
		"offline_access",
	}
	TokenEndpointAuthMethodsSupported = []string{
		"client_secret_basic",
		"client_secret_post",
	}
	ClaimsSupported = []string{
		"sub",
		"email",
		"email_verified",
		"preferred_username",
		"phone_number",
		"address",
		"groups",
		"iss",
		"aud",
	}
	CodeChallengeMethodsSupported = []string{
		cryptography.CodeChallengeMethodPlain,
		cryptography.CodeChallengeMethodS256,
	}
)

type DiscoveryHandler struct {
	issuer                string
	authorizationEndpoint string
	tokenEndpoint         string
	jwksEndpoint          string
	userinfoEndpoint      string
}

type discoveryResponse struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSUri               string `json:"jwks_uri"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`

	GrantTypesSupported               []string `json:"grant_types_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

var _ http.Handler = (*DiscoveryHandler)(nil)

func NewDiscoveryHandler(issuer string, authorizationEndpoint string, tokenEndpoint string, jwksEndpoint string, userinfoEndpoint string) *DiscoveryHandler {
	return &DiscoveryHandler{
		issuer:                issuer,
		authorizationEndpoint: authorizationEndpoint,
		tokenEndpoint:         tokenEndpoint,
		jwksEndpoint:          jwksEndpoint,
		userinfoEndpoint:      userinfoEndpoint,
	}
}

// Discovery renders the OIDC discovery document and partial RFC-8414 authorization
// server metadata hosted at `/.well-known/openid-configuration`.
func (h *DiscoveryHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	discovery := &discoveryResponse{
		Issuer:                h.Issuer(),
		AuthorizationEndpoint: h.AuthorizationEndpoint(),
		TokenEndpoint:         h.TokenEndpoint(),
		JWKSUri:               h.JWKSEndpoint(),
		UserinfoEndpoint:      h.UserinfoEndpoint(),

		GrantTypesSupported:               GrantTypesSupported,
		ResponseTypesSupported:            ResponseTypesSupported,
		SubjectTypesSupported:             SubjectTypesSupported,
		IDTokenSigningAlgValuesSupported:  IDTokenSigningAlgValuesSupported,
		ScopesSupported:                   ScopesSupported,
		TokenEndpointAuthMethodsSupported: TokenEndpointAuthMethodsSupported,
		ClaimsSupported:                   ClaimsSupported,
		CodeChallengeMethodsSupported:     CodeChallengeMethodsSupported,
	}

	resp, err := json.Marshal(discovery)
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	utils.JSON(w, resp)
}

func (h *DiscoveryHandler) Issuer() string {
	return h.issuer
}

func (h *DiscoveryHandler) AuthorizationEndpoint() string {
	return h.issuerWithoutTrailingSlash() + h.authorizationEndpoint
}

func (h *DiscoveryHandler) TokenEndpoint() string {
	return h.issuerWithoutTrailingSlash() + h.tokenEndpoint
}

func (h *DiscoveryHandler) JWKSEndpoint() string {
	return h.issuerWithoutTrailingSlash() + h.jwksEndpoint
}

func (h *DiscoveryHandler) UserinfoEndpoint() string {
	return h.issuerWithoutTrailingSlash() + h.userinfoEndpoint
}

func (h *DiscoveryHandler) issuerWithoutTrailingSlash() string {
	if len(h.issuer) == 0 {
		return ""
	}

	if h.issuer[len(h.issuer)-1] == '/' {
		return h.issuer[:len(h.issuer)-1]
	}

	return h.issuer
}

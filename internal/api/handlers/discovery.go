package handlers

import (
	"net/http"
	"strings"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
)

var (
	GrantTypesSupported = []string{
		"authorization_code",
		"client_credentials",
		"password",
		"refresh_token",
		"urn:ietf:params:oauth:grant-type:jwt-bearer",
		"urn:ietf:params:oauth:grant-type:device_code",
		// "urn:ietf:params:oauth:grant-type:saml2-bearer",
		// "urn:ietf:params:oauth:grant-type:token-exchange",
	}
	ResponseTypesSupported = []string{
		"code",
		"token",
		"token id_token",
		"code id_token",
		"code token",
		"code id_token token",
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
		//"client_secret_jwt",
		//"private_key_jwt",
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
	issuer                      string
	authorizationEndpoint       string
	tokenEndpoint               string
	jwksEndpoint                string
	userinfoEndpoint            string
	introspectionEndpoint       string
	revocationEndpoint          string
	endSessionEndpoint          string
	deviceAuthorizationEndpoint string
}

type discoveryResponse struct {
	Issuer                      string `json:"issuer"`
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	JWKSUri                     string `json:"jwks_uri"`
	UserinfoEndpoint            string `json:"userinfo_endpoint"`
	IntrospectionEndpoint       string `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint          string `json:"revocation_endpoint,omitempty"`
	EndSessionEndpoint          string `json:"end_session_endpoint,omitempty"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint,omitempty"`

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

func NewDiscoveryHandler(issuer, authorizationEndpoint, tokenEndpoint, jwksEndpoint, userinfoEndpoint, introspectionEndpoint, revocationEndpoint, endSessionEndpoint, deviceAuthorizationEndpoint string) *DiscoveryHandler {
	return &DiscoveryHandler{
		issuer:                      issuer,
		authorizationEndpoint:       authorizationEndpoint,
		tokenEndpoint:               tokenEndpoint,
		jwksEndpoint:                jwksEndpoint,
		userinfoEndpoint:            userinfoEndpoint,
		introspectionEndpoint:       introspectionEndpoint,
		revocationEndpoint:          revocationEndpoint,
		endSessionEndpoint:          endSessionEndpoint,
		deviceAuthorizationEndpoint: deviceAuthorizationEndpoint,
	}
}

// Discovery renders the OIDC discovery document and partial RFC-8414 authorization
// server metadata hosted at `/.well-known/openid-configuration`.
func (h *DiscoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	issuer := h.Issuer(r)
	discovery := &discoveryResponse{
		Issuer:                      issuer,
		AuthorizationEndpoint:       h.AuthorizationEndpoint(issuer),
		TokenEndpoint:               h.TokenEndpoint(issuer),
		JWKSUri:                     h.JWKSEndpoint(issuer),
		UserinfoEndpoint:            h.UserinfoEndpoint(issuer),
		IntrospectionEndpoint:       h.IntrospectionEndpoint(issuer),
		RevocationEndpoint:          h.RevocationEndpoint(issuer),
		EndSessionEndpoint:          h.EndSessionEndpoint(issuer),
		DeviceAuthorizationEndpoint: h.DeviceAuthorizationEndpoint(issuer),

		GrantTypesSupported:               GrantTypesSupported,
		ResponseTypesSupported:            ResponseTypesSupported,
		SubjectTypesSupported:             SubjectTypesSupported,
		IDTokenSigningAlgValuesSupported:  IDTokenSigningAlgValuesSupported,
		ScopesSupported:                   ScopesSupported,
		TokenEndpointAuthMethodsSupported: TokenEndpointAuthMethodsSupported,
		ClaimsSupported:                   ClaimsSupported,
		CodeChallengeMethodsSupported:     CodeChallengeMethodsSupported,
	}

	utils.JSON(w, discovery)
}

func (h *DiscoveryHandler) Issuer(r *http.Request) string {
	return utils.GetIssuer(h.issuer, r)
}

func (h *DiscoveryHandler) AuthorizationEndpoint(issuer string) string {
	return issuerWithoutTrailingSlash(issuer) + h.authorizationEndpoint
}

func (h *DiscoveryHandler) TokenEndpoint(issuer string) string {
	return issuerWithoutTrailingSlash(issuer) + h.tokenEndpoint
}

func (h *DiscoveryHandler) JWKSEndpoint(issuer string) string {
	return issuerWithoutTrailingSlash(issuer) + h.jwksEndpoint
}

func (h *DiscoveryHandler) UserinfoEndpoint(issuer string) string {
	return issuerWithoutTrailingSlash(issuer) + h.userinfoEndpoint
}

func (h *DiscoveryHandler) IntrospectionEndpoint(issuer string) string {
	return issuerWithoutTrailingSlash(issuer) + h.introspectionEndpoint
}

func (h *DiscoveryHandler) RevocationEndpoint(issuer string) string {
	return issuerWithoutTrailingSlash(issuer) + h.revocationEndpoint
}

func (h *DiscoveryHandler) EndSessionEndpoint(issuer string) string {
	return issuerWithoutTrailingSlash(issuer) + h.endSessionEndpoint
}

func (h *DiscoveryHandler) DeviceAuthorizationEndpoint(issuer string) string {
	return issuerWithoutTrailingSlash(issuer) + h.deviceAuthorizationEndpoint
}

func issuerWithoutTrailingSlash(issuer string) string {
	return strings.TrimRight(issuer, "/")
}

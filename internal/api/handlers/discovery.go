package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/internal/clientauth"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

var (
	// GrantTypesSupported are the grant types that are always available
	// (the clients must be allowed to use them)
	GrantTypesSupported = []string{
		domain.GrantTypeAuthorizationCode,
		domain.GrantTypeRefreshToken,
		domain.GrantTypeClientCredentials,
		domain.GrantTypeDeviceCode,
		domain.GrantTypeJWTBearer,
	}
	ResponseTypesSupported = []string{
		"code",
	}
	// ImplicitResponseTypesSupported are the response types of the implicit and hybrid flows
	ImplicitResponseTypesSupported = []string{
		"id_token", "id_token token", "code id_token", "code token", "code id_token token",
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
		"address",
		"phone",
		"offline_access",
	}
	TokenEndpointAuthMethodsSupported = []string{
		domain.AuthMethodClientSecretBasic,
		domain.AuthMethodClientSecretPost,
		domain.AuthMethodClientSecretJWT,
		domain.AuthMethodPrivateKeyJWT,
		domain.AuthMethodNone,
	}
	// IntrospectionEndpointAuthMethodsSupported: public clients cannot introspect tokens
	IntrospectionEndpointAuthMethodsSupported = []string{
		domain.AuthMethodClientSecretBasic,
		domain.AuthMethodClientSecretPost,
		domain.AuthMethodClientSecretJWT,
		domain.AuthMethodPrivateKeyJWT,
	}
	TokenEndpointAuthSigningAlgValuesSupported = append(append([]string{}, clientauth.AsymmetricAlgorithms...), clientauth.HMACAlgorithms...)
	ClaimsSupported                            = []string{
		"sub",
		"email",
		"email_verified",
		"preferred_username",
		"name",
		"given_name",
		"family_name",
		"phone_number",
		"address",
		"groups",
		"iss",
		"aud",
		"exp",
		"iat",
		"auth_time",
		"nonce",
		"azp",
		"at_hash",
		"sid",
		"amr",
	}
	ResponseModesSupported = []string{
		"query",
	}
	CodeChallengeMethodsSupported = []string{
		cryptography.CodeChallengeMethodS256,
	}
)

type DiscoveryHandler struct {
	grantTypes     []string
	responseTypes  []string
	responseModes  []string
	deviceEndpoint string

	issuer                string
	authorizationEndpoint string
	tokenEndpoint         string
	jwksEndpoint          string
	userinfoEndpoint      string
	endSessionEndpoint    string
	revocationEndpoint    string
	introspectionEndpoint string
}

type discoveryResponse struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSUri               string `json:"jwks_uri"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	DeviceEndpoint        string `json:"device_authorization_endpoint"`

	GrantTypesSupported               []string `json:"grant_types_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	RevocationEndpointAuthMethods     []string `json:"revocation_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthMethods  []string `json:"introspection_endpoint_auth_methods_supported"`

	TokenEndpointAuthSigningAlgs         []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	RevocationEndpointAuthSigningAlgs    []string `json:"revocation_endpoint_auth_signing_alg_values_supported"`
	IntrospectionEndpointAuthSigningAlgs []string `json:"introspection_endpoint_auth_signing_alg_values_supported"`
	ResponseModesSupported               []string `json:"response_modes_supported"`
	PromptValuesSupported                []string `json:"prompt_values_supported"`

	// request_uri_parameter_supported is true by default, so it must be declared
	RequestParameterSupported         bool `json:"request_parameter_supported"`
	RequestURIParameterSupported      bool `json:"request_uri_parameter_supported"`
	ClaimsParameterSupported          bool `json:"claims_parameter_supported"`
	AuthorizationResponseIssSupported bool `json:"authorization_response_iss_parameter_supported"`
}

var _ http.Handler = (*DiscoveryHandler)(nil)

// DiscoveryEndpoints are the paths of the endpoints published in the discovery document
type DiscoveryEndpoints struct {
	Authorization string
	Token         string
	JWKS          string
	Userinfo      string
	EndSession    string
	Revocation    string
	Introspection string
	Device        string
}

// DiscoveryOptions are the optional features published in the discovery document
type DiscoveryOptions struct {
	AllowImplicitFlow  bool
	AllowPasswordGrant bool
}

func NewDiscoveryHandler(issuer string, endpoints DiscoveryEndpoints, options DiscoveryOptions) *DiscoveryHandler {
	grantTypes := append([]string{}, GrantTypesSupported...)
	responseTypes := append([]string{}, ResponseTypesSupported...)
	responseModes := append([]string{}, ResponseModesSupported...)
	if options.AllowImplicitFlow {
		grantTypes = append(grantTypes, domain.GrantTypeImplicit)
		responseTypes = append(responseTypes, ImplicitResponseTypesSupported...)
		responseModes = append(responseModes, "fragment")
	}
	if options.AllowPasswordGrant {
		grantTypes = append(grantTypes, domain.GrantTypePassword)
	}

	return &DiscoveryHandler{
		grantTypes:            grantTypes,
		responseTypes:         responseTypes,
		responseModes:         responseModes,
		deviceEndpoint:        endpoints.Device,
		issuer:                issuer,
		authorizationEndpoint: endpoints.Authorization,
		tokenEndpoint:         endpoints.Token,
		jwksEndpoint:          endpoints.JWKS,
		userinfoEndpoint:      endpoints.Userinfo,
		endSessionEndpoint:    endpoints.EndSession,
		revocationEndpoint:    endpoints.Revocation,
		introspectionEndpoint: endpoints.Introspection,
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
		EndSessionEndpoint:    h.issuerWithoutTrailingSlash() + h.endSessionEndpoint,
		RevocationEndpoint:    h.issuerWithoutTrailingSlash() + h.revocationEndpoint,
		IntrospectionEndpoint: h.issuerWithoutTrailingSlash() + h.introspectionEndpoint,
		DeviceEndpoint:        h.issuerWithoutTrailingSlash() + h.deviceEndpoint,

		GrantTypesSupported:               h.grantTypes,
		ResponseTypesSupported:            h.responseTypes,
		SubjectTypesSupported:             SubjectTypesSupported,
		IDTokenSigningAlgValuesSupported:  IDTokenSigningAlgValuesSupported,
		ScopesSupported:                   ScopesSupported,
		TokenEndpointAuthMethodsSupported: TokenEndpointAuthMethodsSupported,
		ClaimsSupported:                   ClaimsSupported,
		CodeChallengeMethodsSupported:     CodeChallengeMethodsSupported,
		RevocationEndpointAuthMethods:     TokenEndpointAuthMethodsSupported,
		IntrospectionEndpointAuthMethods:  IntrospectionEndpointAuthMethodsSupported,

		TokenEndpointAuthSigningAlgs:         TokenEndpointAuthSigningAlgValuesSupported,
		RevocationEndpointAuthSigningAlgs:    TokenEndpointAuthSigningAlgValuesSupported,
		IntrospectionEndpointAuthSigningAlgs: TokenEndpointAuthSigningAlgValuesSupported,
		ResponseModesSupported:               h.responseModes,
		PromptValuesSupported:                []string{promptNone, promptLogin, promptConsent, promptSelectAccount},
		AuthorizationResponseIssSupported:    true,
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

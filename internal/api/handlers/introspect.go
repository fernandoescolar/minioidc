package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/golang-jwt/jwt/v5"
)

// IntrospectionHandler implements RFC 7662 token introspection.
//   - Access tokens can be introspected by any confidential client (e.g. the
//     resource servers, registered as clients without redirect URIs).
//   - Refresh tokens can only be introspected by the client they were issued to.
//
// Public clients cannot use it.
type IntrospectionHandler struct {
	now           func() time.Time
	issuer        string
	grantStore    domain.GrantStore
	validator     *accessTokenValidator
	authenticator ClientAuthenticator
	endpointURL   string
}

type introspectionResponse struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Username  string   `json:"username,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	NotBefore int64    `json:"nbf,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	Issuer    string   `json:"iss,omitempty"`
	JWTID     string   `json:"jti,omitempty"`
	SessionID string   `json:"sid,omitempty"`
}

var _ http.Handler = (*IntrospectionHandler)(nil)

func NewIntrospectionHandler(config *domain.Config, now func() time.Time, authenticator ClientAuthenticator, endpointURL string) *IntrospectionHandler {
	return &IntrospectionHandler{
		now:           now,
		issuer:        config.Issuer,
		grantStore:    config.GrantStore,
		validator:     newAccessTokenValidator(config, now),
		authenticator: authenticator,
		endpointURL:   endpointURL,
	}
}

func (h *IntrospectionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.Error(w, utils.InvalidRequest, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		utils.Error(w, utils.InvalidRequest, "Invalid form", http.StatusBadRequest)
		return
	}

	client, ok := authenticateClient(h.authenticator, h.endpointURL, w, r)
	if !ok {
		return
	}

	if client.IsPublic() {
		utils.Error(w, utils.InvalidClient, "Public clients cannot introspect tokens", http.StatusUnauthorized)
		return
	}

	if !assertPresenceInForm([]string{"token"}, w, r) {
		return
	}

	token := r.PostForm.Get("token")
	var resp *introspectionResponse
	// the hint only decides the order: RFC 7662 section 2.1
	if r.PostForm.Get("token_type_hint") == "refresh_token" {
		resp = h.introspectRefreshToken(token, client)
		if resp == nil {
			resp = h.introspectAccessToken(token)
		}
	} else {
		resp = h.introspectAccessToken(token)
		if resp == nil {
			resp = h.introspectRefreshToken(token, client)
		}
	}

	if resp == nil {
		resp = &introspectionResponse{Active: false}
	}

	data, err := json.Marshal(resp)
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	utils.JSON(w, data)
}

func (h *IntrospectionHandler) introspectAccessToken(token string) *introspectionResponse {
	// refresh tokens are opaque: only JWTs can be access tokens
	if strings.Count(token, ".") != 2 {
		return nil
	}

	claims, session, err := h.validator.validate(token)
	if err != nil {
		return nil
	}

	username := ""
	if session != nil {
		username = session.User().Username()
	}

	return &introspectionResponse{
		Active:    true,
		Scope:     claims.Scope,
		ClientID:  claims.ClientID,
		Username:  username,
		TokenType: "Bearer",
		ExpiresAt: claims.ExpiresAt.Unix(),
		IssuedAt:  unixOrZero(claims.IssuedAt),
		NotBefore: unixOrZero(claims.NotBefore),
		Subject:   claims.Subject,
		Audience:  claims.Audience,
		Issuer:    claims.Issuer,
		JWTID:     claims.ID,
		SessionID: claims.SessionID,
	}
}

func (h *IntrospectionHandler) introspectRefreshToken(token string, client domain.Client) *introspectionResponse {
	grant, err := h.grantStore.GetGrantByIDAndType(cryptography.SHA256(token), domain.GrantTypeRefresh)
	if err != nil {
		return nil
	}

	now := h.now()
	if grant.Used() || grant.HasExpired(now) || grant.Session().HasExpired(now) || grant.Client().ClientID() != client.ClientID() {
		return nil
	}

	return &introspectionResponse{
		Active:    true,
		Scope:     strings.Join(grant.Scopes(), " "),
		ClientID:  grant.Client().ClientID(),
		Username:  grant.User().Username(),
		TokenType: "refresh_token",
		ExpiresAt: grant.ExpiresAt().Unix(),
		Subject:   grant.User().ID(),
		Issuer:    h.issuer,
		SessionID: grant.Session().ID(),
	}
}

func unixOrZero(date *jwt.NumericDate) int64 {
	if date == nil {
		return 0
	}

	return date.Unix()
}

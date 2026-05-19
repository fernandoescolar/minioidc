package handlers

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/golang-jwt/jwt"
)

type introspectionRequest struct {
	ClientID     string
	ClientSecret string
	Token        string
	TokenType    string
}

type introspectionResponse struct {
	Active    bool               `json:"active"`
	Scope     string             `json:"scope,omitempty"`
	ClientID  string             `json:"client_id,omitempty"`
	Username  string             `json:"username,omitempty"`
	TokenType string             `json:"token_type,omitempty"`
	ExpiresAt int64              `json:"exp,omitempty"`
	IssuedAt  int64              `json:"iat,omitempty"`
	NotBefore int64              `json:"nbf,omitempty"`
	Sub       string             `json:"sub,omitempty"`
	Audience  domain.StringArray `json:"aud,omitempty"`
	Issuer    string             `json:"iss,omitempty"`

	JWTID string `json:"jti,omitempty"`
}

type IntrospectionHandler struct {
	now         func() time.Time
	issuer      string
	audience    string
	keypair     *cryptography.Keypair
	clientStore domain.ClientStore
	grantStore  domain.GrantStore
	masterKey   string
}

var _ http.Handler = (*IntrospectionHandler)(nil)

func NewIntrospectionHandler(config *domain.Config, now func() time.Time) *IntrospectionHandler {
	return &IntrospectionHandler{
		now:      now,
		issuer:   config.Issuer,
		audience: config.Audience,

		keypair:     config.Keypair,
		clientStore: config.ClientStore,
		grantStore:  config.GrantStore,
		masterKey:   config.MasterKey,
	}
}

func (h *IntrospectionHandler) Issuer(r *http.Request) string {
	return utils.GetIssuer(h.issuer, r)
}

func (h *IntrospectionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.Error(w, utils.InvalidRequest, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	req, err := parseIntrospectionRequest(r)
	if err != nil {
		utils.Error(w, utils.InvalidRequest, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Token == "" {
		utils.ErrorMissingParameter(w, "token")
		return
	}

	client, err := h.clientStore.GetClientByID(req.ClientID)
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	if client == nil {
		utils.Error(w, utils.InvalidClient, "Invalid client", http.StatusUnauthorized)
		return
	}

	if !client.ClientSecretIsValid(req.ClientSecret) {
		utils.Error(w, utils.InvalidClient, "Invalid client", http.StatusUnauthorized)
		return
	}

	if req.TokenType == "" {
		req.TokenType = "access_token"
	}

	switch req.TokenType {
	case "access_token":
		h.introspectAccessToken(req, w)
	case "refresh_token":
		h.introspectRefreshToken(req, w, r)
	default:
		utils.Error(w, utils.InvalidRequest, "Unsupported token type", http.StatusBadRequest)
	}
}

func parseIntrospectionRequest(r *http.Request) (*introspectionRequest, error) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		return nil, errors.New("missing client credentials")
	}

	err := r.ParseForm()
	if err != nil {
		return nil, err
	}

	return &introspectionRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Token:        r.Form.Get("token"),
		TokenType:    r.Form.Get("token_type_hint"),
	}, nil
}

func (h *IntrospectionHandler) introspectAccessToken(req *introspectionRequest, w http.ResponseWriter) {
	token, ok := utils.ValidateJWT(req.Token, h.keypair, h.now())
	if !ok {
		errorInactiveToken(w)
		return
	}

	res := &introspectionResponse{
		Active: true,
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok {
		if exp, ok := claims["exp"].(float64); ok {
			res.ExpiresAt = int64(exp)
		}
		if iat, ok := claims["iat"].(float64); ok {
			res.IssuedAt = int64(iat)
		}
		if nbf, ok := claims["nbf"].(float64); ok {
			res.NotBefore = int64(nbf)
		}
		if sub, ok := claims["sub"].(string); ok {
			res.Sub = sub
		}
		if iss, ok := claims["iss"].(string); ok {
			res.Issuer = iss
		}
		if aud, ok := claims["aud"].([]string); ok {
			res.Audience = aud
		}
		if jti, ok := claims["jti"].(string); ok {
			res.JWTID = jti
		}
	}

	utils.JSON(w, res)

}

func (h *IntrospectionHandler) introspectRefreshToken(req *introspectionRequest, w http.ResponseWriter, r *http.Request) {
	dr, err := cryptography.Decrypts(h.masterKey, req.Token)
	if err != nil {
		log.Println("Error: getting refresh token: %w", err)
		errorInactiveToken(w)
		return
	}

	hr := cryptography.SHA256(dr)
	grant, err := h.grantStore.GetGrantByIDAndType(hr, domain.GrantTypeRefresh)
	if err != nil {
		errorInactiveToken(w)
		return
	}

	if grant == nil {
		errorInactiveToken(w)
		return
	}

	res := &introspectionResponse{
		Active: true,
	}

	res.ClientID = grant.Client().ClientID()
	if len(grant.Scopes()) > 0 {
		res.Scope = strings.Join(grant.Scopes(), " ")
	}
	res.Username = grant.User().Username()
	res.TokenType = "refresh_token"
	res.ExpiresAt = grant.ExpiresAtUnix()
	res.IssuedAt = grant.IssuedAtUnix()
	res.NotBefore = grant.IssuedAtUnix()
	res.Sub = grant.User().ID()
	audiencies := grant.Client().GetAudiences()
	if h.audience != "" {
		audiencies = append(audiencies, h.audience)
	}
	res.Audience = domain.StringArray(audiencies)
	res.Issuer = h.Issuer(r)

	utils.JSON(w, res)
}

func errorInactiveToken(w http.ResponseWriter) {
	utils.JSON(w, map[string]string{"active": "false"})
}

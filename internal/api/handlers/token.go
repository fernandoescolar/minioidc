package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/internal/stores"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

const (
	openidScope        = "openid"
	offlineAccessScope = "offline_access"
)

type TokenHandler struct {
	now                func() time.Time
	issuer             string
	audience           string
	masterKey          string
	reUseRefreshTokens bool
	keypair            *cryptography.Keypair
	accessTTL          time.Duration
	refreshTTL         time.Duration
	clientStore        domain.ClientStore
	grantStore         domain.GrantStore
	userStore          domain.UserStore
}

type tokenRequest struct {
	GrantType    string
	ClientID     string
	ClientSecret string
	Scopes       []string
	// authorization_code
	Code         string
	RedirectURI  string
	CodeVerifier string
	// refresh_token
	RefreshToken string
	// password
	Username string
	Password string
	// client_credentials

	// device_code
	DeviceCode string
	// jwt-bearer and saml2-bearer
	Assertion string
	// token-exchange
	SubjectToken     string
	SubjectTokenType string
	ActorToken       string
	ActorTokenType   string
	Audience         string
	Resource         string
}

type tokenResponse struct {
	AccessToken  string        `json:"access_token,omitempty"`
	RefreshToken string        `json:"refresh_token,omitempty"`
	IDToken      string        `json:"id_token,omitempty"`
	TokenType    string        `json:"token_type"`
	ExpiresIn    time.Duration `json:"expires_in"`
}

var _ http.Handler = (*TokenHandler)(nil)

func NewTokenHandler(config *domain.Config, now func() time.Time) *TokenHandler {
	return &TokenHandler{
		now:                now,
		issuer:             config.Issuer,
		audience:           config.Audience,
		masterKey:          config.MasterKey,
		reUseRefreshTokens: config.ReuseRefreshTokens,
		keypair:            config.Keypair,
		accessTTL:          config.AccessTTL,
		refreshTTL:         config.RefreshTTL,
		clientStore:        config.ClientStore,
		grantStore:         config.GrantStore,
		userStore:          config.UserStore,
	}
}

func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.Error(w, utils.InvalidRequest, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	tokenReq, err := h.parseTokenRequest(r)
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	var grant domain.Grant
	switch tokenReq.GrantType {
	case "authorization_code":
		grant = h.authorizationCodeGrant(tokenReq, w)
	case "refresh_token":
		grant = h.refreshTokenGrant(tokenReq, w)
	case "password":
		grant = h.passwordGrant(tokenReq, w)
	case "client_credentials":
		grant = h.clientCredentialsGrant(tokenReq, w)
	case "urn:ietf:params:oauth:grant-type:device_code":
		utils.Error(w, utils.UnsupportedGrantType, "Device code grant type is not supported", http.StatusBadRequest)
	case "urn:ietf:params:oauth:grant-type:jwt-bearer":
		utils.Error(w, utils.UnsupportedGrantType, "JWT bearer grant type is not supported", http.StatusBadRequest)
	case "urn:ietf:params:oauth:grant-type:saml2-bearer":
		utils.Error(w, utils.UnsupportedGrantType, "SAML2 bearer grant type is not supported", http.StatusBadRequest)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		utils.Error(w, utils.UnsupportedGrantType, "Token exchange grant type is not supported", http.StatusBadRequest)
	default:
		utils.Error(w, utils.InvalidRequest, fmt.Sprintf("Invalid grant type: %s", tokenReq.GrantType), http.StatusBadRequest)
	}

	if grant == nil {
		return
	}

	h.createTokenResponse(grant, tokenReq, w)
}

func (h *TokenHandler) parseTokenRequest(r *http.Request) (*tokenRequest, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, err
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}

	return &tokenRequest{
		GrantType:        r.Form.Get("grant_type"),
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		Scopes:           utils.ParseSpaceSeparatedString(r.Form.Get("scope")),
		Code:             r.Form.Get("code"),
		RedirectURI:      r.Form.Get("redirect_uri"),
		CodeVerifier:     r.Form.Get("code_verifier"),
		RefreshToken:     r.Form.Get("refresh_token"),
		Username:         r.Form.Get("username"),
		Password:         r.Form.Get("password"),
		DeviceCode:       r.Form.Get("device_code"),
		Assertion:        r.Form.Get("assertion"),
		SubjectToken:     r.Form.Get("subject_token"),
		SubjectTokenType: r.Form.Get("subject_token_type"),
		ActorToken:       r.Form.Get("actor_token"),
		ActorTokenType:   r.Form.Get("actor_token_type"),
		Audience:         r.Form.Get("audience"),
		Resource:         r.Form.Get("resource"),
	}, nil
}

func (h *TokenHandler) createRefreshToken(grant domain.Grant, w http.ResponseWriter) (string, bool) {
	id := stores.CreateComplexUID()
	hid := cryptography.SHA256(id)
	eid, err := cryptography.Encrypts(h.masterKey, id)
	if err != nil {
		log.Println("Error: creating refresh token id: %w", err)
		utils.InternalServerError(w, err.Error())
		return "", false
	}

	_, err = h.grantStore.NewRefreshTokenGrant(hid, grant.Client(), grant.Session(), h.now().Add(h.refreshTTL), grant.Scopes())
	if err != nil {
		log.Println("Error: creating refresh token: %w", err)
		utils.InternalServerError(w, err.Error())
		return "", false
	}

	return eid, true
}

func (h *TokenHandler) createTokenResponse(grant domain.Grant, tokenReq *tokenRequest, w http.ResponseWriter) {
	tokens := &tokenResponse{
		TokenType: "bearer",
		ExpiresIn: h.accessTTL,
	}
	var err error

	tokens.AccessToken, err = grant.AccessToken(h.issuer, h.audience, h.accessTTL, h.keypair, h.now())
	if err != nil {
		log.Println("Error: creating access token: %w", err)
		utils.InternalServerError(w, err.Error())
		return
	}

	if len(grant.Scopes()) > 0 && grant.Scopes()[0] == openidScope {
		tokens.IDToken, err = grant.IDToken(h.issuer, h.audience, h.refreshTTL, h.keypair, h.now())
		if err != nil {
			log.Println("Error: creating id token: %w", err)
			utils.InternalServerError(w, err.Error())
			return
		}
	}

	if tokenReq.GrantType == "refresh_token" && h.reUseRefreshTokens {
		tokens.RefreshToken = tokenReq.RefreshToken
	}
	if containsOfflineAccess(grant.Scopes()) || (tokenReq.GrantType == "refresh_token" && !h.reUseRefreshTokens) {
		id, success := h.createRefreshToken(grant, w)
		if !success {
			return
		}

		tokens.RefreshToken = id
	}

	resp, err := json.Marshal(tokens)
	if err != nil {
		log.Println("Error: marshaling tokens: %w", err)
		utils.InternalServerError(w, err.Error())
		return
	}

	utils.NoCache(w)
	utils.JSON(w, resp)
}

func containsOfflineAccess(scopes []string) bool {
	for _, scope := range scopes {
		if scope == offlineAccessScope {
			return true
		}
	}

	return false
}

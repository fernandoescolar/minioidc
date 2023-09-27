package handlers

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/handlers/responses"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

const (
	openidScope        = "openid"
	offlineAccessScope = "offline_access"
)

type TokenHandler struct {
	now         func() time.Time
	issuer      string
	audience    string
	keypair     *cryptography.Keypair
	accessTTL   time.Duration
	refreshTTL  time.Duration
	clientStore domain.ClientStore
	grantStore  domain.GrantStore
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
		now:         now,
		issuer:      config.Issuer,
		audience:    config.Audience,
		keypair:     config.Keypair,
		accessTTL:   config.AccessTTL,
		refreshTTL:  config.RefreshTTL,
		clientStore: config.ClientStore,
		grantStore:  config.GrantStore,
	}
}

func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responses.Error(w, responses.InvalidRequest, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseForm()
	if err != nil {
		responses.InternalServerError(w, err.Error())
		return
	}

	grantType := r.Form.Get("grant_type")
	switch grantType {
	case "authorization_code":
		h.requestWithCode(w, r)
		return
	case "refresh_token":
		h.requestWithRefresh(w, r)
		return
	default:
		responses.Error(w, responses.InvalidRequest, fmt.Sprintf("Invalid grant type: %s", grantType), http.StatusBadRequest)
		return
	}
}

func (h *TokenHandler) requestWithCode(w http.ResponseWriter, r *http.Request) bool {
	grant, valid := h.validateCodeGrant(w, r)
	if !valid {
		return false
	}

	if !h.validateCodeChallenge(w, r, grant) {
		return false
	}

	tokens := &tokenResponse{
		TokenType: "bearer",
		ExpiresIn: h.accessTTL,
	}
	var err error

	tokens.AccessToken, err = grant.AccessToken(h.issuer, h.audience, h.accessTTL, h.keypair, h.now())
	if err != nil {
		responses.InternalServerError(w, err.Error())
		return false
	}

	if len(grant.Scopes()) > 0 && grant.Scopes()[0] == openidScope {
		tokens.IDToken, err = grant.IDToken(h.issuer, h.audience, h.refreshTTL, h.keypair, h.now())
		if err != nil {
			responses.InternalServerError(w, err.Error())
			return false
		}
	}

	if containsOfflineAccess(grant.Scopes()) {
		refreshGrant, err := h.grantStore.NewRefreshTokenGrant(grant.Client(), grant.Session(), h.now().Add(h.refreshTTL), grant.Scopes())
		if err != nil {
			responses.InternalServerError(w, err.Error())
			return false
		}

		tokens.RefreshToken = refreshGrant.ID()
	}

	resp, err := json.Marshal(tokens)
	if err != nil {
		responses.InternalServerError(w, err.Error())
		return false
	}

	responses.NoCache(w)
	responses.JSON(w, resp)

	return true
}

func (h *TokenHandler) requestWithRefresh(w http.ResponseWriter, r *http.Request) bool {
	grant, valid := h.validateRefreshGrant(w, r)
	if !valid {
		return false
	}

	tokens := &tokenResponse{
		TokenType:    "bearer",
		ExpiresIn:    h.accessTTL,
		RefreshToken: grant.ID(),
	}
	var err error

	tokens.AccessToken, err = grant.AccessToken(h.issuer, h.audience, h.accessTTL, h.keypair, h.now())
	if err != nil {
		responses.InternalServerError(w, err.Error())
		return false
	}

	if len(grant.Scopes()) > 0 && grant.Scopes()[0] == openidScope {
		tokens.IDToken, err = grant.IDToken(h.issuer, h.audience, h.refreshTTL, h.keypair, h.now())
		if err != nil {
			responses.InternalServerError(w, err.Error())
			return false
		}
	}

	resp, err := json.Marshal(tokens)
	if err != nil {
		responses.InternalServerError(w, err.Error())
		return false
	}

	responses.NoCache(w)
	responses.JSON(w, resp)

	return true
}

func (h *TokenHandler) validateCodeGrant(w http.ResponseWriter, r *http.Request) (domain.Grant, bool) {
	if !assertPresenceInForm([]string{"code", "redirect_uri"}, w, r) {
		return nil, false
	}
	equal := assertEqualInForm("grant_type", "authorization_code", responses.UnsupportedGrantType, "Invalid grant type", w, r)
	if !equal {
		return nil, false
	}

	code := r.Form.Get("code")
	grant, err := h.grantStore.GetGrantByIDAndType(code, domain.GrantTypeCode)
	if err != nil || grant.HasBeenGranted() {
		responses.Error(w, responses.InvalidGrant, fmt.Sprintf("Invalid code: %s", code), http.StatusUnauthorized)
		return nil, false
	}

	redirectURI := r.Form.Get("redirect_uri")
	if !grant.Client().RedirectURLIsValid(redirectURI) {
		responses.Error(w, responses.InvalidRequest, "Invalid redirect uri", http.StatusBadRequest)
		return nil, false
	}

	if err := h.grantStore.Grant(grant.ID()); err != nil {
		log.Println("Error granting code:", err)
	}

	return grant, true
}

func (h *TokenHandler) validateCodeChallenge(w http.ResponseWriter, r *http.Request, grant domain.Grant) bool {
	if grant.CodeChallenge() == "" || grant.CodeChallengeMethod() == "" {
		return true
	}

	codeVerifier := r.Form.Get("code_verifier")
	if codeVerifier == "" {
		responses.Error(w, responses.InvalidGrant, "Invalid code verifier. Expected code but client sent none.", http.StatusUnauthorized)
		return false
	}

	challenge, err := cryptography.GenerateCodeChallenge(grant.CodeChallengeMethod(), codeVerifier)
	if err != nil {
		responses.Error(w, responses.InvalidRequest, fmt.Sprintf("Invalid code verifier. %v", err.Error()), http.StatusUnauthorized)
		return false
	}

	if challenge != grant.CodeChallenge() {
		responses.Error(w, responses.InvalidGrant, "Invalid code verifier. Code challenge did not match hashed code verifier.", http.StatusUnauthorized)
		return false
	}

	return true
}

func (h *TokenHandler) validateRefreshGrant(w http.ResponseWriter, r *http.Request) (domain.Grant, bool) {
	if !assertPresenceInForm([]string{"refresh_token"}, w, r) {
		return nil, false
	}

	equal := assertEqualInForm("grant_type", "refresh_token", responses.UnsupportedGrantType, "Invalid grant type", w, r)
	if !equal {
		return nil, false
	}

	if !assertPresenceInForm([]string{"client_id", "client_secret"}, w, r) {
		return nil, false
	}

	_, err := h.clientStore.GetClientByID(r.Form.Get("client_id"))
	if err != nil {
		responses.Error(w, responses.InvalidClient, "Invalid client id", http.StatusUnauthorized)
		return nil, false
	}

	// validSecret := client.ClientSecretIsValid(req.Form.Get("client_secret"))
	// if !validSecret {
	// 	errorResponse(rw, InvalidClient, "Invalid client secret", http.StatusUnauthorized)
	// 	return nil, false
	// }

	refreshToken := r.Form.Get("refresh_token")
	grant, err := h.grantStore.GetGrantByIDAndType(refreshToken, domain.GrantTypeRefresh)
	if err != nil {
		responses.Error(w, responses.InvalidGrant, "Invalid refresh token",
			http.StatusUnauthorized)
		return nil, false
	}

	return grant, true
}

func assertPresenceInForm(params []string, rw http.ResponseWriter, req *http.Request) bool {
	for _, param := range params {
		if req.Form.Get(param) != "" {
			continue
		}
		responses.Error(
			rw,
			responses.InvalidRequest,
			fmt.Sprintf("The request is missing the required parameter: %s", param),
			http.StatusBadRequest,
		)
		return false
	}
	return true
}

func assertEqualInForm(param, value, errorType, errorMsg string, w http.ResponseWriter, r *http.Request) bool {
	formValue := r.Form.Get(param)
	if subtle.ConstantTimeCompare([]byte(value), []byte(formValue)) == 0 {
		responses.Error(w, errorType, fmt.Sprintf("%s: %s", errorMsg, formValue),
			http.StatusUnauthorized)
		return false
	}
	return true
}

func containsOfflineAccess(scopes []string) bool {
	for _, scope := range scopes {
		if scope == offlineAccessScope {
			return true
		}
	}

	return false
}

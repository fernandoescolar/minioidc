package handlers

import (
	"crypto/subtle"
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
	}
}

func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.Error(w, utils.InvalidRequest, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseForm()
	if err != nil {
		utils.InternalServerError(w, err.Error())
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
		utils.Error(w, utils.InvalidRequest, fmt.Sprintf("Invalid grant type: %s", grantType), http.StatusBadRequest)
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
		log.Println("Error: creating access token: %w", err)
		utils.InternalServerError(w, err.Error())
		return false
	}

	if len(grant.Scopes()) > 0 && grant.Scopes()[0] == openidScope {
		tokens.IDToken, err = grant.IDToken(h.issuer, h.audience, h.refreshTTL, h.keypair, h.now())
		if err != nil {
			log.Println("Error: creating id token: %w", err)
			utils.InternalServerError(w, err.Error())
			return false
		}
	}

	if containsOfflineAccess(grant.Scopes()) {
		id, success := h.createRefreshToken(w, grant)
		if !success {
			return false
		}

		tokens.RefreshToken = id
	}

	resp, err := json.Marshal(tokens)
	if err != nil {
		log.Println("Error: marshaling tokens: %w", err)
		utils.InternalServerError(w, err.Error())
		return false
	}

	utils.NoCache(w)
	utils.JSON(w, resp)

	return true
}

func (h *TokenHandler) requestWithRefresh(w http.ResponseWriter, r *http.Request) bool {
	grant, valid := h.validateRefreshGrant(w, r)
	if !valid {
		return false
	}

	tokens := &tokenResponse{
		TokenType: "bearer",
		ExpiresIn: h.accessTTL,
	}

	if h.reUseRefreshTokens {
		tokens.RefreshToken = r.Form.Get("refresh_token")
	} else {
		id, success := h.createRefreshToken(w, grant)
		if !success {
			log.Println("Error creating new refresh token")
			utils.InternalServerError(w, "Error creating new refresh token")
			return false
		}

		tokens.RefreshToken = id
	}

	var err error

	tokens.AccessToken, err = grant.AccessToken(h.issuer, h.audience, h.accessTTL, h.keypair, h.now())
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return false
	}

	if len(grant.Scopes()) > 0 && grant.Scopes()[0] == openidScope {
		tokens.IDToken, err = grant.IDToken(h.issuer, h.audience, h.refreshTTL, h.keypair, h.now())
		if err != nil {
			utils.InternalServerError(w, err.Error())
			return false
		}
	}

	resp, err := json.Marshal(tokens)
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return false
	}

	utils.NoCache(w)
	utils.JSON(w, resp)

	return true
}

func (h *TokenHandler) validateCodeGrant(w http.ResponseWriter, r *http.Request) (domain.Grant, bool) {
	if !assertPresenceInForm([]string{"code", "redirect_uri"}, w, r) {
		return nil, false
	}
	equal := assertEqualInForm("grant_type", "authorization_code", utils.UnsupportedGrantType, "Invalid grant type", w, r)
	if !equal {
		return nil, false
	}

	code := r.Form.Get("code")
	code, err := cryptography.Decrypts(h.masterKey, code)
	if err != nil {
		log.Println("Error: getting code: %w", err)
		utils.InternalServerError(w, err.Error())
		return nil, false
	}

	code = cryptography.SHA256(code)
	grant, err := h.grantStore.GetGrantByIDAndType(code, domain.GrantTypeCode)
	if err != nil || grant.HasBeenGranted() {
		utils.Error(w, utils.InvalidGrant, fmt.Sprintf("Invalid code: %s", code), http.StatusUnauthorized)
		return nil, false
	}

	redirectURI := r.Form.Get("redirect_uri")
	if !grant.Client().RedirectURLIsValid(redirectURI) {
		utils.Error(w, utils.InvalidRequest, "Invalid redirect uri", http.StatusBadRequest)
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
		utils.Error(w, utils.InvalidGrant, "Invalid code verifier. Expected code but client sent none.", http.StatusUnauthorized)
		return false
	}

	challenge, err := cryptography.GenerateCodeChallenge(grant.CodeChallengeMethod(), codeVerifier)
	if err != nil {
		utils.Error(w, utils.InvalidRequest, fmt.Sprintf("Invalid code verifier. %v", err.Error()), http.StatusUnauthorized)
		return false
	}

	if challenge != grant.CodeChallenge() {
		utils.Error(w, utils.InvalidGrant, "Invalid code verifier. Code challenge did not match hashed code verifier.", http.StatusUnauthorized)
		return false
	}

	return true
}

func (h *TokenHandler) validateRefreshGrant(w http.ResponseWriter, r *http.Request) (domain.Grant, bool) {
	if !assertPresenceInForm([]string{"refresh_token"}, w, r) {
		return nil, false
	}

	equal := assertEqualInForm("grant_type", "refresh_token", utils.UnsupportedGrantType, "Invalid grant type", w, r)
	if !equal {
		return nil, false
	}

	if !assertPresenceInForm([]string{"client_id", "client_secret"}, w, r) {
		return nil, false
	}

	_, err := h.clientStore.GetClientByID(r.Form.Get("client_id"))
	if err != nil {
		utils.Error(w, utils.InvalidClient, "Invalid client id", http.StatusUnauthorized)
		return nil, false
	}

	// validSecret := client.ClientSecretIsValid(req.Form.Get("client_secret"))
	// if !validSecret {
	// 	errorResponse(rw, InvalidClient, "Invalid client secret", http.StatusUnauthorized)
	// 	return nil, false
	// }

	refreshToken := r.Form.Get("refresh_token")
	dr, err := cryptography.Decrypts(h.masterKey, refreshToken)
	if err != nil {
		log.Println("Error: getting refresh token: %w", err)
		utils.InternalServerError(w, err.Error())
		return nil, false
	}

	hr := cryptography.SHA256(dr)
	grant, err := h.grantStore.GetGrantByIDAndType(hr, domain.GrantTypeRefresh)
	if err != nil {
		utils.Error(w, utils.InvalidGrant, "Invalid refresh token",
			http.StatusUnauthorized)
		return nil, false
	}

	if !h.reUseRefreshTokens {
		h.grantStore.Grant(grant.ID())
	}

	return grant, true
}

func assertPresenceInForm(params []string, rw http.ResponseWriter, req *http.Request) bool {
	for _, param := range params {
		if req.Form.Get(param) != "" {
			continue
		}
		utils.Error(
			rw,
			utils.InvalidRequest,
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
		utils.Error(w, errorType, fmt.Sprintf("%s: %s", errorMsg, formValue),
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

func (h *TokenHandler) createRefreshToken(w http.ResponseWriter, grant domain.Grant) (string, bool) {
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

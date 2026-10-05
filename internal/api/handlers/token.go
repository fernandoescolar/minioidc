package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/internal/credentials"
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
	reUseRefreshTokens bool
	keypair            *cryptography.Keypair
	accessTTL          time.Duration
	refreshTTL         time.Duration
	sessionTTL         time.Duration
	allowPassword      bool
	grantStore         domain.GrantStore
	sessionStore       domain.SessionStore
	userStore          domain.UserStore
	userStates         domain.UserStateStore
	events             *domain.Recorder
	deviceCodeStore    domain.DeviceCodeStore
	credentials        *credentials.Checker
	authenticator      ClientAuthenticator
	endpointURL        string
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

var _ http.Handler = (*TokenHandler)(nil)

func NewTokenHandler(config *domain.Config, now func() time.Time, authenticator ClientAuthenticator, endpointURL string) *TokenHandler {
	return &TokenHandler{
		now:                now,
		issuer:             config.Issuer,
		audience:           config.Audience,
		reUseRefreshTokens: config.ReuseRefreshTokens,
		keypair:            config.Keypair,
		accessTTL:          config.AccessTTL,
		refreshTTL:         config.RefreshTTL,
		sessionTTL:         config.SessionTTL,
		allowPassword:      config.AllowPasswordGrant,
		grantStore:         config.GrantStore,
		sessionStore:       config.SessionStore,
		userStore:          config.UserStore,
		userStates:         config.UserStateStore,
		events:             config.Events,
		deviceCodeStore:    config.DeviceCodeStore,
		credentials: &credentials.Checker{
			Users:      config.UserStore,
			MFA:        config.MFACodeStore,
			Blocked:    config.UserBlockedStore,
			RequireMFA: config.RequireMFA,
			States:     config.UserStateStore,
		},
		authenticator: authenticator,
		endpointURL:   endpointURL,
	}
}

func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	grantType := r.PostForm.Get("grant_type")
	handler, supported := map[string]func(http.ResponseWriter, *http.Request, domain.Client){
		domain.GrantTypeAuthorizationCode: h.requestWithCode,
		domain.GrantTypeRefreshToken:      h.requestWithRefresh,
		domain.GrantTypeClientCredentials: h.requestWithClientCredentials,
		domain.GrantTypePassword:          h.requestWithPassword,
		domain.GrantTypeDeviceCode:        h.requestWithDeviceCode,
		domain.GrantTypeJWTBearer:         h.requestWithJWTBearer,
	}[grantType]

	// the password grant is discouraged (RFC 9700): it must be enabled in the configuration
	if !supported || (grantType == domain.GrantTypePassword && !h.allowPassword) {
		utils.Error(w, utils.UnsupportedGrantType, fmt.Sprintf("Unsupported grant type: %s", grantType), http.StatusBadRequest)
		return
	}

	if !client.GrantTypeAllowed(grantType) {
		utils.Error(w, utils.UnauthorizedClient, "The client is not allowed to use this grant type", http.StatusBadRequest)
		return
	}

	handler(w, r, client)
}

func (h *TokenHandler) requestWithCode(w http.ResponseWriter, r *http.Request, client domain.Client) {
	if !assertPresenceInForm([]string{"code", "redirect_uri"}, w, r) {
		return
	}

	grant, ok := h.consumeGrant(w, r.PostForm.Get("code"), domain.GrantTypeCode, client)
	if !ok {
		return
	}

	// RFC 6749 section 4.1.3: it must be identical to the one of the authorization request
	if r.PostForm.Get("redirect_uri") != grant.RedirectURI() {
		utils.Error(w, utils.InvalidGrant, "Invalid redirect uri", http.StatusBadRequest)
		return
	}

	if grant.CodeChallenge() != "" &&
		!cryptography.VerifyCodeChallenge(grant.CodeChallengeMethod(), grant.CodeChallenge(), r.PostForm.Get("code_verifier")) {
		utils.Error(w, utils.InvalidGrant, "Invalid code verifier", http.StatusBadRequest)
		return
	}

	refreshToken := ""
	if grant.HasScope(offlineAccessScope) {
		var err error
		refreshToken, err = h.createRefreshToken(grant)
		if err != nil {
			utils.InternalServerError(w, err.Error())
			return
		}
	}

	h.writeTokens(w, grant, refreshToken, true)
}

func (h *TokenHandler) requestWithRefresh(w http.ResponseWriter, r *http.Request, client domain.Client) {
	if !assertPresenceInForm([]string{"refresh_token"}, w, r) {
		return
	}

	refreshToken := r.PostForm.Get("refresh_token")
	var (
		grant domain.Grant
		ok    bool
	)
	if h.reUseRefreshTokens {
		grant, ok = h.getGrant(w, refreshToken, domain.GrantTypeRefresh, client)
	} else {
		grant, ok = h.consumeGrant(w, refreshToken, domain.GrantTypeRefresh, client)
	}
	if !ok {
		return
	}

	if !h.reUseRefreshTokens {
		var err error
		refreshToken, err = h.createRefreshToken(grant)
		if err != nil {
			utils.InternalServerError(w, err.Error())
			return
		}
	}

	h.writeTokens(w, grant, refreshToken, true)
}

// getGrant looks up a valid grant issued to the client
func (h *TokenHandler) getGrant(w http.ResponseWriter, token string, grantType domain.GrantType, client domain.Client) (domain.Grant, bool) {
	grant, err := h.grantStore.GetGrantByIDAndType(cryptography.SHA256(token), grantType)
	if err != nil {
		utils.Error(w, utils.InvalidGrant, "Invalid or expired grant", http.StatusBadRequest)
		return nil, false
	}

	if grant.Used() {
		h.revokeReplayedGrant(grant)
		utils.Error(w, utils.InvalidGrant, "Invalid or expired grant", http.StatusBadRequest)
		return nil, false
	}

	now := h.now()
	if grant.HasExpired(now) || grant.Session().HasExpired(now) || grant.Client().ClientID() != client.ClientID() {
		utils.Error(w, utils.InvalidGrant, "Invalid or expired grant", http.StatusBadRequest)
		return nil, false
	}

	// the user may have left the allowed groups of the client since the grant
	if !client.UserAllowed(grant.User()) {
		utils.Error(w, utils.InvalidGrant, "The user cannot use this client", http.StatusBadRequest)
		return nil, false
	}

	return grant, true
}

// consumeGrant looks up a valid grant and consumes it, so it can only be used once
func (h *TokenHandler) consumeGrant(w http.ResponseWriter, token string, grantType domain.GrantType, client domain.Client) (domain.Grant, bool) {
	grant, ok := h.getGrant(w, token, grantType, client)
	if !ok {
		return nil, false
	}

	if err := h.grantStore.Grant(grant.ID()); err != nil {
		// another request consumed it at the same time
		h.revokeReplayedGrant(grant)
		utils.Error(w, utils.InvalidGrant, "Invalid or expired grant", http.StatusBadRequest)
		return nil, false
	}

	return grant, true
}

// revokeReplayedGrant revokes the refresh tokens issued from a code or a
// rotated refresh token that is used twice (RFC 6749 section 4.1.2 and
// RFC 9700 section 4.14.2): one of the requests could be from an attacker.
func (h *TokenHandler) revokeReplayedGrant(grant domain.Grant) {
	log.Printf("WRN %s grant used twice: revoking the tokens issued from it", grant.GrantType())
	if err := h.grantStore.RevokeFamily(grant.FamilyID()); err != nil {
		log.Printf("Error: revoking grant family: %v", err)
	}
}

// writeTokens writes the access token, the refresh token (if any) and, when
// idToken is true and the scopes have openid, the ID token
func (h *TokenHandler) writeTokens(w http.ResponseWriter, grant domain.Grant, refreshToken string, idToken bool) {
	now := h.now()
	accessToken, err := grant.AccessToken(h.issuer, h.audience, h.accessTTL, h.keypair, now)
	if err != nil {
		utils.InternalServerError(w, fmt.Sprintf("creating access token: %v", err))
		return
	}

	tokens := &tokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(h.accessTTL.Seconds()),
		Scope:        strings.Join(grant.Scopes(), " "),
	}

	if idToken && grant.HasScope(openidScope) {
		tokens.IDToken, err = grant.IDToken(h.issuer, h.accessTTL, h.keypair, now, accessToken, "")
		if err != nil {
			utils.InternalServerError(w, fmt.Sprintf("creating id token: %v", err))
			return
		}
	}

	resp, err := json.Marshal(tokens)
	if err != nil {
		utils.InternalServerError(w, fmt.Sprintf("marshaling tokens: %v", err))
		return
	}

	utils.JSON(w, resp)
}

func (h *TokenHandler) createRefreshToken(grant domain.Grant) (string, error) {
	token, err := cryptography.RandomToken()
	if err != nil {
		return "", fmt.Errorf("creating refresh token: %w", err)
	}

	_, err = h.grantStore.NewRefreshTokenGrant(cryptography.SHA256(token), grant.FamilyID(), grant.Client(), grant.Session(), h.now().Add(h.refreshTTL), grant.Scopes())
	if err != nil {
		return "", fmt.Errorf("creating refresh token: %w", err)
	}

	return token, nil
}

func assertPresenceInForm(params []string, w http.ResponseWriter, r *http.Request) bool {
	for _, param := range params {
		if r.PostForm.Get(param) != "" {
			continue
		}
		utils.Error(
			w,
			utils.InvalidRequest,
			fmt.Sprintf("The request is missing the required parameter: %s", param),
			http.StatusBadRequest,
		)
		return false
	}
	return true
}

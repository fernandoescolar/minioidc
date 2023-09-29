package handlers

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type AuthorizeHandler struct {
	now           func() time.Time
	codeTTL       time.Duration
	loginEndpoint string
	clientStore   domain.ClientStore
	grantStore    domain.GrantStore
	sessionStore  domain.SessionStore
	masterKey     string
}

var _ http.Handler = (*AuthorizeHandler)(nil)

func NewAuthorizeHandler(config *domain.Config, now func() time.Time, loginEndpoint string) *AuthorizeHandler {
	return &AuthorizeHandler{
		now:           now,
		codeTTL:       config.CodeTTL,
		loginEndpoint: loginEndpoint,
		clientStore:   config.ClientStore,
		grantStore:    config.GrantStore,
		sessionStore:  config.SessionStore,
		masterKey:     config.MasterKey,
	}
}

func (h *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.Error(w, utils.InvalidRequest, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	valid := assertPresenceInQuery([]string{"scope", "state", "client_id", "response_type", "redirect_uri"}, w, r)
	if !valid {
		return
	}

	if !validateScope(w, r) {
		return
	}

	client, err := h.clientStore.GetClientByID(r.URL.Query().Get("client_id"))
	if err != nil {
		utils.Error(w, utils.InvalidClient, "Invalid client id", http.StatusUnauthorized)
		return
	}

	validRedirectURI := client.RedirectURLIsValid(r.URL.Query().Get("redirect_uri"))
	if !validRedirectURI {
		utils.Error(w, utils.InvalidRequest, "Invalid redirect uri", http.StatusBadRequest)
		return
	}

	validType := assertEqualInQuery("response_type", "code",
		utils.UnsupportedGrantType, "Invalid response type", w, r)
	if !validType {
		return
	}
	if !validateCodeChallengeMethodSupported(w, r.URL.Query().Get("code_challenge_method"), CodeChallengeMethodsSupported) {
		return
	}

	session := utils.GetSession(r)
	if session == nil {
		// the session should be handled in the SessionAuthorized middleware
		utils.InternalServerError(w, "Session not found")
		return
	}

	grant, err := h.grantStore.NewCodeGrant(
		client,
		session,
		h.now().Add(h.codeTTL),
		strings.Split(r.URL.Query().Get("scope"), " "),
		r.URL.Query().Get("nonce"),
		r.URL.Query().Get("code_challenge"),
		r.URL.Query().Get("code_challenge_method"),
	)
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	redirectURI, err := url.Parse(r.URL.Query().Get("redirect_uri"))
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}
	params, _ := url.ParseQuery(redirectURI.RawQuery)
	params.Set("code", grant.ID())
	params.Set("state", r.URL.Query().Get("state"))
	redirectURI.RawQuery = params.Encode()
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}

func (h *AuthorizeHandler) getAuthenticatedUserFromCookies(r *http.Request) domain.Session {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil
	}

	encryptedSessionID := cookie.Value
	if encryptedSessionID == "" {
		return nil
	}

	sessionID, err := cryptography.Decrypts(encryptedSessionID, h.masterKey)
	if sessionID == "" || err != nil {
		return nil
	}

	session, err := h.sessionStore.GetSessionByID(sessionID)
	if session == nil || err != nil {
		return nil
	}

	return session
}

func validateScope(w http.ResponseWriter, r *http.Request) bool {
	allowed := make(map[string]struct{})
	for _, scope := range ScopesSupported {
		allowed[scope] = struct{}{}
	}

	scopes := strings.Split(r.URL.Query().Get("scope"), " ")
	for _, scope := range scopes {
		if _, ok := allowed[scope]; !ok {
			utils.Error(w, utils.InvalidScope, fmt.Sprintf("Unsupported scope: %s", scope),
				http.StatusBadRequest)
			return false
		}
	}
	return true
}

func validateCodeChallengeMethodSupported(w http.ResponseWriter, method string, supportedMethods []string) bool {
	if method != "" && !contains(method, supportedMethods) {
		utils.Error(w, utils.InvalidRequest, "Invalid code challenge method", http.StatusBadRequest)
		return false
	}
	return true
}

func assertPresenceInQuery(params []string, w http.ResponseWriter, r *http.Request) bool {
	for _, param := range params {
		if r.URL.Query().Get(param) != "" {
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

func assertEqualInQuery(param, value, errorType, errorMsg string, w http.ResponseWriter, r *http.Request) bool {
	queryValue := r.URL.Query().Get(param)
	if subtle.ConstantTimeCompare([]byte(value), []byte(queryValue)) == 0 {
		utils.Error(w, errorType, fmt.Sprintf("%s: %s", errorMsg, queryValue),
			http.StatusUnauthorized)
		return false
	}
	return true
}

func contains(value string, list []string) bool {
	for _, element := range list {
		if element == value {
			return true
		}
	}
	return false
}

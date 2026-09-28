package handlers

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/golang-jwt/jwt/v5"
)

const (
	maxScopeLength = 200

	promptNone          = "none"
	promptLogin         = "login"
	promptConsent       = "consent"
	promptSelectAccount = "select_account"
)

// AuthorizeHandler implements the authorization endpoint. It handles the
// session itself (instead of the SessionAuthorized middleware) because the
// prompt, max_age and id_token_hint parameters decide if the user must log in.
type AuthorizeHandler struct {
	now           func() time.Time
	issuer        string
	masterKey     string
	codeTTL       time.Duration
	sessionTTL    time.Duration
	keypair       *cryptography.Keypair
	clientStore   domain.ClientStore
	grantStore    domain.GrantStore
	sessionStore  domain.SessionStore
	loginEndpoint string
	mfaEndpoint   string
}

// authorizeRequest is a validated authorization request
type authorizeRequest struct {
	params      url.Values
	client      domain.Client
	redirectURL *url.URL
	prompt      map[string]bool
	maxAge      int64
	hasMaxAge   bool
	hint        *domain.IDTokenClaims
}

var _ http.Handler = (*AuthorizeHandler)(nil)

func NewAuthorizeHandler(config *domain.Config, now func() time.Time, loginEndpoint, mfaEndpoint string) *AuthorizeHandler {
	return &AuthorizeHandler{
		now:           now,
		issuer:        config.Issuer,
		masterKey:     config.MasterKey,
		codeTTL:       config.CodeTTL,
		sessionTTL:    config.SessionTTL,
		keypair:       config.Keypair,
		clientStore:   config.ClientStore,
		grantStore:    config.GrantStore,
		sessionStore:  config.SessionStore,
		loginEndpoint: loginEndpoint,
		mfaEndpoint:   mfaEndpoint,
	}
}

func (h *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// OIDC Core section 3.1.2.1: GET and POST must be supported
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		utils.Error(w, utils.InvalidRequest, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		utils.Error(w, utils.InvalidRequest, "Invalid request", http.StatusBadRequest)
		return
	}

	req, ok := h.validateClient(w, r.Form)
	if !ok {
		return
	}

	// from here on, the errors are sent to the client
	if errCode, description := h.validateRequest(req); errCode != "" {
		h.redirectError(w, r, req, errCode, description)
		return
	}

	session := h.currentSession(r)
	if h.mustLogin(req, session) {
		if req.prompt[promptNone] {
			h.redirectError(w, r, req, utils.LoginRequired, "The user must log in")
			return
		}

		h.redirectToLogin(w, r, req)
		return
	}

	if session.MFARequired() {
		if req.prompt[promptNone] {
			h.redirectError(w, r, req, utils.InteractionRequired, "The user must verify the MFA code")
			return
		}

		location := h.mfaEndpoint + "?return_url=" + url.QueryEscape(authorizeURL(r, req.params))
		http.Redirect(w, r, location, http.StatusFound)
		return
	}

	if err := h.sessionStore.UpdateTTL(session.ID(), h.now().Add(h.sessionTTL)); err != nil {
		log.Printf("Failed to update session TTL: %v", err)
	}

	code, err := h.createCode(req, session)
	if err != nil {
		log.Printf("Error: authorize: %v", err)
		h.redirectError(w, r, req, utils.ServerError, "")
		return
	}

	h.redirect(w, r, req, url.Values{"code": {code}})
}

// validateClient validates the client and the redirect_uri. Until they are
// validated the errors are shown to the user and never redirected (RFC 6749
// section 4.1.2.1).
func (h *AuthorizeHandler) validateClient(w http.ResponseWriter, params url.Values) (*authorizeRequest, bool) {
	if !assertPresenceInQuery([]string{"client_id", "redirect_uri"}, w, params) {
		return nil, false
	}

	client, err := h.clientStore.GetClientByID(params.Get("client_id"))
	if err != nil {
		utils.Error(w, utils.InvalidClient, "Invalid client id", http.StatusBadRequest)
		return nil, false
	}

	redirectURI := params.Get("redirect_uri")
	redirectURL, err := url.Parse(redirectURI)
	if !client.RedirectURLIsValid(redirectURI) || err != nil {
		utils.Error(w, utils.InvalidRequest, "Invalid redirect uri", http.StatusBadRequest)
		return nil, false
	}

	return &authorizeRequest{params: params, client: client, redirectURL: redirectURL}, true
}

// validateRequest returns the OAuth error code and description of an invalid request
func (h *AuthorizeHandler) validateRequest(req *authorizeRequest) (string, string) {
	params := req.params
	if params.Get("request") != "" {
		return utils.RequestNotSupported, "Request objects are not supported"
	}

	if params.Get("request_uri") != "" {
		return utils.RequestURINotSupported, "Request objects are not supported"
	}

	for _, param := range []string{"response_type", "scope"} {
		if params.Get(param) == "" {
			return utils.InvalidRequest, fmt.Sprintf("The request is missing the required parameter: %s", param)
		}
	}

	if params.Get("response_type") != "code" {
		return utils.UnsupportedResponse, "Only the code response type is supported"
	}

	if mode := params.Get("response_mode"); mode != "" && mode != "query" {
		return utils.InvalidRequest, "Only the query response mode is supported"
	}

	if errCode, description := validateScope(params.Get("scope")); errCode != "" {
		return errCode, description
	}

	if errCode, description := validateCodeChallenge(req.client, params.Get("code_challenge"), params.Get("code_challenge_method")); errCode != "" {
		return errCode, description
	}

	req.prompt = map[string]bool{}
	for _, value := range strings.Fields(params.Get("prompt")) {
		if !contains(value, []string{promptNone, promptLogin, promptConsent, promptSelectAccount}) {
			return utils.InvalidRequest, fmt.Sprintf("Unsupported prompt: %s", value)
		}

		req.prompt[value] = true
	}

	if req.prompt[promptNone] && len(req.prompt) > 1 {
		return utils.InvalidRequest, "The prompt none cannot be combined with other values"
	}

	if value := params.Get("max_age"); value != "" {
		maxAge, err := strconv.ParseInt(value, 10, 64)
		if err != nil || maxAge < 0 {
			return utils.InvalidRequest, "Invalid max_age"
		}

		req.maxAge, req.hasMaxAge = maxAge, true
	}

	if hint := params.Get("id_token_hint"); hint != "" {
		claims := &domain.IDTokenClaims{}
		_, err := h.keypair.VerifyJWT(hint, claims, jwt.WithoutClaimsValidation())
		if err != nil || claims.Issuer != h.issuer {
			return utils.InvalidRequest, "Invalid id_token_hint"
		}

		req.hint = claims
	}

	return "", ""
}

// mustLogin returns true if the user has to log in (again)
func (h *AuthorizeHandler) mustLogin(req *authorizeRequest, session domain.Session) bool {
	if session == nil {
		return true
	}

	// consent is implicit: the clients are registered by the administrator
	if req.prompt[promptLogin] || req.prompt[promptSelectAccount] {
		return true
	}

	if req.hasMaxAge && h.now().Sub(session.AuthTime()) > time.Duration(req.maxAge)*time.Second {
		return true
	}

	return req.hint != nil && req.hint.Subject != session.User().ID()
}

func (h *AuthorizeHandler) currentSession(r *http.Request) domain.Session {
	sessionID := utils.GetSessionIDFromCookie(r, h.masterKey)
	if sessionID == "" {
		return nil
	}

	session, err := h.sessionStore.GetSessionByID(sessionID)
	if err != nil || session.HasExpired(h.now()) {
		return nil
	}

	return session
}

// redirectToLogin sends the user to the login page. The parameters that ask
// for a new login are removed from the return URL, so the request does not
// ask for it again after the login.
func (h *AuthorizeHandler) redirectToLogin(w http.ResponseWriter, r *http.Request, req *authorizeRequest) {
	params := url.Values{}
	for key, values := range req.params {
		params[key] = values
	}

	params.Del("max_age")
	prompt := []string{}
	for value := range req.prompt {
		if value != promptLogin && value != promptSelectAccount {
			prompt = append(prompt, value)
		}
	}
	if len(prompt) > 0 {
		params.Set("prompt", strings.Join(prompt, " "))
	} else {
		params.Del("prompt")
	}

	login := url.Values{"return_url": {authorizeURL(r, params)}}
	if hint := req.params.Get("login_hint"); hint != "" {
		login.Set("login_hint", hint)
	}

	http.Redirect(w, r, h.loginEndpoint+"?"+login.Encode(), http.StatusFound)
}

func (h *AuthorizeHandler) createCode(req *authorizeRequest, session domain.Session) (string, error) {
	code, err := cryptography.RandomToken()
	if err != nil {
		return "", fmt.Errorf("creating code: %w", err)
	}

	params := req.params
	_, err = h.grantStore.NewCodeGrant(
		cryptography.SHA256(code),
		req.client,
		session,
		h.now().Add(h.codeTTL),
		strings.Split(params.Get("scope"), " "),
		params.Get("nonce"),
		params.Get("code_challenge"),
		params.Get("code_challenge_method"),
		params.Get("redirect_uri"),
	)
	if err != nil {
		return "", fmt.Errorf("creating code grant: %w", err)
	}

	return code, nil
}

func (h *AuthorizeHandler) redirectError(w http.ResponseWriter, r *http.Request, req *authorizeRequest, errCode, description string) {
	params := url.Values{"error": {errCode}}
	if description != "" {
		params.Set("error_description", description)
	}

	h.redirect(w, r, req, params)
}

// redirect sends the response to the client, adding the state and the issuer
// (RFC 9207) and keeping the query parameters of the redirect_uri
func (h *AuthorizeHandler) redirect(w http.ResponseWriter, r *http.Request, req *authorizeRequest, params url.Values) {
	u := *req.redirectURL
	query := u.Query()
	for key := range params {
		query.Set(key, params.Get(key))
	}

	if state := req.params.Get("state"); state != "" {
		query.Set("state", state)
	}

	query.Set("iss", h.issuer)
	u.RawQuery = query.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}

// authorizeURL is the local URL of the authorization request (also for POST requests)
func authorizeURL(r *http.Request, params url.Values) string {
	return r.URL.Path + "?" + params.Encode()
}

func validateScope(scope string) (string, string) {
	if len(scope) > maxScopeLength {
		return utils.InvalidScope, "Invalid scope"
	}

	for _, s := range strings.Split(scope, " ") {
		if !contains(s, ScopesSupported) {
			return utils.InvalidScope, fmt.Sprintf("Unsupported scope: %s", s)
		}
	}

	return "", ""
}

// validateCodeChallenge only accepts S256 and makes PKCE mandatory for public clients
func validateCodeChallenge(client domain.Client, challenge, method string) (string, string) {
	if challenge == "" {
		if method != "" || client.IsPublic() {
			return utils.InvalidRequest, "code_challenge is required"
		}

		return "", ""
	}

	if method != cryptography.CodeChallengeMethodS256 {
		return utils.InvalidRequest, "Invalid code challenge method. Only S256 is supported"
	}

	return "", ""
}

func assertPresenceInQuery(params []string, w http.ResponseWriter, query url.Values) bool {
	for _, param := range params {
		if query.Get(param) != "" {
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

func contains(value string, list []string) bool {
	for _, element := range list {
		if element == value {
			return true
		}
	}
	return false
}

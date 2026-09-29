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
	accessTTL     time.Duration
	audience      string
	allowImplicit bool
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
	// responseTypes are the words of response_type (code, token, id_token)
	responseTypes map[string]bool
	// fragment is true when the response goes in the fragment of the redirect_uri
	fragment  bool
	prompt    map[string]bool
	maxAge    int64
	hasMaxAge bool
	hint      *domain.IDTokenClaims
}

var _ http.Handler = (*AuthorizeHandler)(nil)

func NewAuthorizeHandler(config *domain.Config, now func() time.Time, loginEndpoint, mfaEndpoint string) *AuthorizeHandler {
	return &AuthorizeHandler{
		now:           now,
		issuer:        config.Issuer,
		masterKey:     config.MasterKey,
		codeTTL:       config.CodeTTL,
		accessTTL:     config.AccessTTL,
		audience:      config.Audience,
		allowImplicit: config.AllowImplicitFlow,
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

	params, err := h.createResponse(req, session)
	if err != nil {
		log.Printf("Error: authorize: %v", err)
		h.redirectError(w, r, req, utils.ServerError, "")
		return
	}

	h.redirect(w, r, req, params)
}

// createResponse creates the code and, in the implicit and hybrid flows, the
// access token and the ID token (never a refresh token: they are sent
// through the browser)
func (h *AuthorizeHandler) createResponse(req *authorizeRequest, session domain.Session) (url.Values, error) {
	params := url.Values{}
	code := ""
	if req.responseTypes["code"] {
		var err error
		if code, err = h.createCode(req, session); err != nil {
			return nil, err
		}
		params.Set("code", code)
	}

	if !req.responseTypes["token"] && !req.responseTypes["id_token"] {
		return params, nil
	}

	id, err := cryptography.RandomToken()
	if err != nil {
		return nil, err
	}

	now := h.now()
	grant := domain.NewGrant(domain.GrantData{
		ID:        cryptography.SHA256(id),
		FamilyID:  cryptography.SHA256(id),
		GrantType: domain.GrantTypeCode,
		ExpiresAt: now.Add(h.accessTTL),
		Scopes:    strings.Fields(req.params.Get("scope")),
		Nonce:     req.params.Get("nonce"),
	}, req.client, session)

	accessToken := ""
	if req.responseTypes["token"] {
		if accessToken, err = grant.AccessToken(h.issuer, h.audience, h.accessTTL, h.keypair, now); err != nil {
			return nil, err
		}
		params.Set("access_token", accessToken)
		params.Set("token_type", "Bearer")
		params.Set("expires_in", strconv.FormatInt(int64(h.accessTTL.Seconds()), 10))
	}

	if req.responseTypes["id_token"] {
		idToken, err := grant.IDToken(h.issuer, h.accessTTL, h.keypair, now, accessToken, code)
		if err != nil {
			return nil, err
		}
		params.Set("id_token", idToken)
	}

	return params, nil
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

	// the errors of the implicit and hybrid flows go in the fragment too (OIDC Core 3.2.2.6)
	words := " " + params.Get("response_type") + " "
	mode := params.Get("response_mode")
	fragment := mode == "fragment" || (mode == "" && (strings.Contains(words, " token ") || strings.Contains(words, " id_token ")))

	return &authorizeRequest{
		params:        params,
		client:        client,
		redirectURL:   redirectURL,
		responseTypes: map[string]bool{},
		fragment:      fragment,
	}, true
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

	if errCode, description := h.validateResponseType(req); errCode != "" {
		return errCode, description
	}

	if errCode, description := validateScope(params.Get("scope")); errCode != "" {
		return errCode, description
	}

	// PKCE protects the code: the implicit flow has no code
	if req.responseTypes["code"] {
		if errCode, description := validateCodeChallenge(req.client, params.Get("code_challenge"), params.Get("code_challenge_method")); errCode != "" {
			return errCode, description
		}
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

// validateResponseType checks the response_type and the response_mode. The
// implicit and hybrid flows (token or id_token) are discouraged (RFC 9700):
// they must be enabled in the configuration and allowed to the client.
func (h *AuthorizeHandler) validateResponseType(req *authorizeRequest) (string, string) {
	words := strings.Fields(req.params.Get("response_type"))
	for _, word := range words {
		if !contains(word, []string{"code", "token", "id_token"}) || req.responseTypes[word] {
			return utils.UnsupportedResponse, "Unsupported response_type"
		}
		req.responseTypes[word] = true
	}

	if len(words) == 0 {
		return utils.InvalidRequest, "The request is missing the required parameter: response_type"
	}

	implicit := req.responseTypes["token"] || req.responseTypes["id_token"]
	switch {
	case implicit && !h.allowImplicit:
		return utils.UnsupportedResponse, "The implicit and hybrid flows are disabled"
	case implicit && !req.client.GrantTypeAllowed(domain.GrantTypeImplicit):
		return utils.UnauthorizedClient, "The client is not allowed to use the implicit and hybrid flows"
	case req.responseTypes["code"] && !req.client.GrantTypeAllowed(domain.GrantTypeAuthorizationCode):
		return utils.UnauthorizedClient, "The client is not allowed to use the authorization code flow"
	}

	switch req.params.Get("response_mode") {
	case "":
	case "fragment":
		req.fragment = true
	case "query":
		// OIDC Core 3.2.2.5: the tokens must not be sent in the query
		if implicit {
			return utils.InvalidRequest, "The query response mode cannot be used with tokens"
		}
	default:
		return utils.InvalidRequest, "Unsupported response_mode"
	}

	// OIDC Core 3.2.2.1: the nonce is required when the ID token is returned in the front channel
	if req.responseTypes["id_token"] && req.params.Get("nonce") == "" {
		return utils.InvalidRequest, "The nonce is required with the id_token response type"
	}

	if req.responseTypes["id_token"] && !contains(openidScope, strings.Fields(req.params.Get("scope"))) {
		return utils.InvalidScope, "The id_token response type requires the openid scope"
	}

	return "", ""
}

// redirect sends the response to the client, adding the state and the issuer
// (RFC 9207). It goes in the query, keeping the parameters of the
// redirect_uri, or in the fragment (implicit and hybrid flows).
func (h *AuthorizeHandler) redirect(w http.ResponseWriter, r *http.Request, req *authorizeRequest, params url.Values) {
	values := url.Values{}
	for key := range params {
		values.Set(key, params.Get(key))
	}

	if state := req.params.Get("state"); state != "" {
		values.Set("state", state)
	}
	values.Set("iss", h.issuer)

	u := *req.redirectURL
	if req.fragment {
		u.Fragment = ""
		u.RawFragment = ""
		http.Redirect(w, r, u.String()+"#"+values.Encode(), http.StatusFound)
		return
	}

	query := u.Query()
	for key := range values {
		query.Set(key, values.Get(key))
	}
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

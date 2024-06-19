package handlers

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/internal/stores"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type authRequest struct {
	Scopes       []string
	ResponseType string
	ClientID     string
	RedirectURI  string

	State string
	Nonce string

	ResponseMode string
	Prompt       string
	MaxAge       *uint
	UILocales    string
	IDTokenHint  string
	LoginHint    string
	ACRValues    []string

	CodeChallenge       string
	CodeChallengeMethod string

	// RequestParam enables OIDC requests to be passed in a single, self-contained parameter (as JWT, called Request Object)
	RequestParam string
}

type AuthorizeHandler struct {
	now            func() time.Time
	issuer         string
	audience       string
	keypair        *cryptography.Keypair
	codeTTL        time.Duration
	accessTokenTTL time.Duration
	loginEndpoint  string
	clientStore    domain.ClientStore
	grantStore     domain.GrantStore
	sessionStore   domain.SessionStore
	masterKey      string
}

var _ http.Handler = (*AuthorizeHandler)(nil)

func NewAuthorizeHandler(config *domain.Config, now func() time.Time, loginEndpoint string) *AuthorizeHandler {
	return &AuthorizeHandler{
		now:            now,
		issuer:         config.Issuer,
		audience:       config.Audience,
		keypair:        config.Keypair,
		codeTTL:        config.CodeTTL,
		accessTokenTTL: config.AccessTTL,
		loginEndpoint:  loginEndpoint,
		clientStore:    config.ClientStore,
		grantStore:     config.GrantStore,
		sessionStore:   config.SessionStore,
		masterKey:      config.MasterKey,
	}
}

func (h *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		utils.Error(w, utils.InvalidRequest, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	authReq, err := parseAuthRequest(r)
	if err != nil {
		utils.Error(w, utils.InvalidRequest, "Invalid request", http.StatusBadRequest)
		return
	}

	if authReq.State == "" {
		utils.ErrorMissingParameter(w, "state")
		return
	}

	if authReq.ClientID == "" {
		utils.ErrorMissingParameter(w, "client_id")
		return
	}

	if authReq.ResponseType == "" {
		utils.ErrorMissingParameter(w, "response_type")
		return
	}

	if authReq.RedirectURI == "" {
		utils.ErrorMissingParameter(w, "redirect_uri")
		return
	}

	client, err := h.clientStore.GetClientByID(authReq.ClientID)
	if err != nil {
		utils.Error(w, utils.InvalidRequest, "Invalid client id", http.StatusUnauthorized)
		return
	}

	if !client.RedirectURLIsValid(authReq.RedirectURI) {
		utils.Error(w, utils.UnsupportedRequestUri, "Invalid redirect uri", http.StatusBadRequest)
		return
	}

	if !client.ScopesAreValid(authReq.Scopes) {
		return
	}

	if !client.ResponseTypeIsValid(authReq.ResponseType) {
		utils.Error(w, utils.InvalidRequest, "Invalid response type", http.StatusBadRequest)
		return
	}

	if authReq.CodeChallengeMethod != "" && !slices.Contains(CodeChallengeMethodsSupported, authReq.CodeChallengeMethod) {
		utils.Error(w, utils.InvalidRequest, "Invalid code challenge method", http.StatusBadRequest)
		return
	}

	session := utils.GetSession(r)
	if session == nil {
		// the session should be handled in the SessionAuthorized middleware
		utils.InternalServerError(w, "Session not found")
		return
	}

	utils.AddRedirectToCSPHeader(w, authReq.RedirectURI)

	id := stores.CreateComplexUID()
	hid := cryptography.SHA256(id)

	var code, idToken, accessToken string
	if strings.Contains(authReq.ResponseType, "code") {
		code, err = h.createCodeGrant(id, hid, client, session, authReq)
		if err != nil {
			utils.InternalServerError(w, err.Error())
			return
		}
	}
	if strings.Contains(authReq.ResponseType, "token") || strings.Contains(authReq.ResponseType, "id_token") {
		grant := h.createDefaultGrant(id, client, session, authReq)
		if strings.Contains(authReq.ResponseType, "token") {
			accessToken, err = grant.AccessToken(h.issuer, h.audience, h.accessTokenTTL, h.keypair, h.now())
			if err != nil {
				utils.InternalServerError(w, err.Error())
				return
			}
		}
		if strings.Contains(authReq.ResponseType, "id_token") {
			idToken, err = grant.IDToken(h.issuer, h.audience, h.accessTokenTTL, h.keypair, h.now())
			if err != nil {
				utils.InternalServerError(w, err.Error())
				return
			}
		}
	}

	switch authReq.ResponseType {
	// code
	case "code":
		h.codeResponseType(code, authReq, w, r)
	// implicit
	case "token", "token id_token":
		h.implicitResponseType(accessToken, idToken, authReq, w, r)
	// hybrid
	case "code id_token", "code token", "code id_token token":
		h.hybridResponseType(code, idToken, accessToken, authReq, w, r)
	default:
		utils.Error(w, utils.UnsupportedRequest, "Unsupported response type", http.StatusBadRequest)
	}
}

func parseAuthRequest(r *http.Request) (*authRequest, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, err
	}

	maxAge, err := utils.ParsePtrUint(r.Form.Get("max_age"))
	if err != nil {
		return nil, err
	}

	return &authRequest{
		Scopes:              utils.ParseSpaceSeparatedString(r.Form.Get("scope")),
		ResponseType:        r.Form.Get("response_type"),
		ClientID:            r.Form.Get("client_id"),
		RedirectURI:         r.Form.Get("redirect_uri"),
		State:               r.Form.Get("state"),
		Nonce:               r.Form.Get("nonce"),
		ResponseMode:        r.Form.Get("response_mode"),
		Prompt:              r.Form.Get("prompt"),
		MaxAge:              maxAge,
		UILocales:           r.Form.Get("ui_locales"),
		IDTokenHint:         r.Form.Get("id_token_hint"),
		LoginHint:           r.Form.Get("login_hint"),
		ACRValues:           utils.ParseSpaceSeparatedString(r.Form.Get("acr_values")),
		CodeChallenge:       r.Form.Get("code_challenge"),
		CodeChallengeMethod: r.Form.Get("code_challenge_method"),
		RequestParam:        r.Form.Get("request"),
	}, nil
}

func (h *AuthorizeHandler) createCodeGrant(id, hid string, client domain.Client, session domain.Session, authReq *authRequest) (string, error) {
	eid, err := cryptography.Encrypts(h.masterKey, id)
	if err != nil {
		return "", err
	}

	ttl := client.GetAccessTokenTTL()
	if ttl == nil {
		ttl = &h.codeTTL
	}

	_, err = h.grantStore.NewCodeGrant(
		hid,
		client,
		session,
		h.now().Add(*ttl),
		authReq.Scopes,
		authReq.Nonce,
		authReq.CodeChallenge,
		authReq.CodeChallengeMethod,
	)

	return eid, err
}

func (h *AuthorizeHandler) createDefaultGrant(id string, client domain.Client, session domain.Session, authReq *authRequest) domain.Grant {
	return domain.NewGrant(
		id,
		domain.GrantTypeCode,
		client,
		session,
		h.now().Add(h.codeTTL),
		authReq.Scopes,
		authReq.Nonce,
		authReq.CodeChallenge,
		authReq.CodeChallengeMethod)
}

func (h *AuthorizeHandler) codeResponseType(code string, authReq *authRequest, w http.ResponseWriter, r *http.Request) {
	ru, err := url.Parse(authReq.RedirectURI)
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	params, _ := url.ParseQuery(ru.RawQuery)
	params.Set("code", code)
	params.Set("state", authReq.State)
	ru.RawQuery = params.Encode()

	http.Redirect(w, r, ru.String(), http.StatusFound)
}

func (h *AuthorizeHandler) implicitResponseType(token, idToken string, authReq *authRequest, w http.ResponseWriter, r *http.Request) {
	ru, err := url.Parse(authReq.RedirectURI)
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	params, _ := url.ParseQuery(ru.RawQuery)
	params.Set("access_token", token)
	params.Set("id_token", idToken)
	params.Set("state", authReq.State)
	params.Set("token_type", "Bearer")
	params.Set("expires_in", h.accessTokenTTL.String())
	ru.RawQuery = params.Encode()

	url := ru.String()
	url = strings.Replace(url, "?", "#", 1)
	http.Redirect(w, r, url, http.StatusFound)
}

func (h *AuthorizeHandler) hybridResponseType(code, idToken, token string, authReq *authRequest, w http.ResponseWriter, r *http.Request) {
	ru, err := url.Parse(authReq.RedirectURI)
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	params, _ := url.ParseQuery(ru.RawQuery)
	params.Set("code", code)
	params.Set("id_token", idToken)
	params.Set("access_token", token)
	params.Set("state", authReq.State)
	params.Set("token_type", "Bearer")
	params.Set("expires_in", h.accessTokenTTL.String())
	ru.RawQuery = params.Encode()

	url := ru.String()
	url = strings.Replace(url, "?", "#", 1)

	http.Redirect(w, r, url, http.StatusFound)
}

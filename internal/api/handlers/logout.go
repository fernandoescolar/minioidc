package handlers

import (
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/golang-jwt/jwt/v5"
)

// LogoutHandler implements OIDC RP-Initiated Logout (end_session_endpoint)
type LogoutHandler struct {
	name          string
	now           func() time.Time
	issuer        string
	masterKey     string
	secureCookies bool
	keypair       *cryptography.Keypair
	clientStore   domain.ClientStore
	sessionStore  domain.SessionStore
	template      *template.Template
}

type logoutModel struct {
	Name                  string
	CSRF                  string
	LoggedOut             bool
	IDTokenHint           string
	ClientID              string
	PostLogoutRedirectURI string
	State                 string
	FormExpired           bool
}

var _ http.Handler = (*LogoutHandler)(nil)

func NewLogoutHandler(config *domain.Config, now func() time.Time) *LogoutHandler {
	return &LogoutHandler{
		name:          config.Name,
		now:           now,
		issuer:        config.Issuer,
		masterKey:     config.MasterKey,
		secureCookies: config.UseSecureCookie,
		keypair:       config.Keypair,
		clientStore:   config.ClientStore,
		sessionStore:  config.SessionStore,
		template:      utils.ParseTemplates(config.BasePath, config.BaseTemplateFilepath, config.LogoutTemplateFilepath),
	}
}

func (h *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	if err := r.ParseForm(); err != nil {
		utils.Error(w, utils.InvalidRequest, "Invalid form", http.StatusBadRequest)
		return
	}

	model := logoutModel{
		Name:                  h.name,
		CSRF:                  utils.GetCSRFToken(r),
		IDTokenHint:           r.Form.Get("id_token_hint"),
		ClientID:              r.Form.Get("client_id"),
		PostLogoutRedirectURI: r.Form.Get("post_logout_redirect_uri"),
		State:                 r.Form.Get("state"),
	}

	hint, validHint := h.parseIDTokenHint(model.IDTokenHint)
	if model.IDTokenHint != "" && !validHint {
		utils.Error(w, utils.InvalidRequest, "Invalid id_token_hint", http.StatusBadRequest)
		return
	}

	if model.PostLogoutRedirectURI != "" && !h.validPostLogoutRedirectURI(model, hint) {
		utils.Error(w, utils.InvalidRequest, "Invalid post_logout_redirect_uri", http.StatusBadRequest)
		return
	}

	sessionID := utils.GetSessionIDFromCookie(r, h.masterKey)
	if r.Method == http.MethodGet {
		// log out without confirmation only when the client proves it is the
		// session that is being closed; otherwise, ask the user to confirm
		if !validHint || (sessionID != "" && hint.SessionID != sessionID) {
			utils.RenderTemplate(w, h.template, model)
			return
		}
	} else if !utils.GetCSRFValid(r) {
		model.FormExpired = true
		utils.RenderTemplateStatus(w, http.StatusBadRequest, h.template, model)
		return
	}

	if sessionID != "" {
		_ = h.sessionStore.DeleteSession(sessionID)
	}
	utils.ClearSessionCookie(w, h.secureCookies)

	if model.PostLogoutRedirectURI != "" {
		h.redirect(w, r, model)
		return
	}

	model.LoggedOut = true
	utils.RenderTemplate(w, h.template, model)
}

// parseIDTokenHint verifies an ID token issued by this server. Expired tokens are valid hints.
func (h *LogoutHandler) parseIDTokenHint(hint string) (*domain.IDTokenClaims, bool) {
	if hint == "" {
		return nil, false
	}

	claims := &domain.IDTokenClaims{}
	_, err := h.keypair.VerifyJWT(hint, claims, jwt.WithoutClaimsValidation())
	if err != nil || claims.Issuer != h.issuer {
		return nil, false
	}

	return claims, true
}

func (h *LogoutHandler) validPostLogoutRedirectURI(model logoutModel, hint *domain.IDTokenClaims) bool {
	clientID := model.ClientID
	if hint != nil {
		hintClientID := hint.AuthorizedParty
		if hintClientID == "" && len(hint.Audience) > 0 {
			hintClientID = hint.Audience[0]
		}

		if clientID != "" && clientID != hintClientID {
			return false
		}

		clientID = hintClientID
	}

	if clientID == "" {
		return false
	}

	client, err := h.clientStore.GetClientByID(clientID)
	return err == nil && client.PostLogoutRedirectURLIsValid(model.PostLogoutRedirectURI)
}

func (h *LogoutHandler) redirect(w http.ResponseWriter, r *http.Request, model logoutModel) {
	u, err := url.Parse(model.PostLogoutRedirectURI)
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	if model.State != "" {
		params := u.Query()
		params.Set("state", model.State)
		u.RawQuery = params.Encode()
	}

	http.Redirect(w, r, u.String(), http.StatusFound)
}

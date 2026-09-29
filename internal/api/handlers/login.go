package handlers

import (
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/internal/stores"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type LoginHandler struct {
	name          string
	now           func() time.Time
	template      *template.Template
	sessionTTL    time.Duration
	sessionStore  domain.SessionStore
	userStore     domain.UserStore
	userBlocked   domain.UserBlockedStore
	masterKey     string
	requireMFA    bool
	secureCookies bool
	home          string
	setup         *SetupHandler
	setupURL      string
}

type loginModel struct {
	Name            string
	Username        string
	InvalidLogin    bool
	TooManyAttempts bool
	UnknownError    bool
	FormExpired     bool
	CSRF            string
}

var _ http.Handler = (*LoginHandler)(nil)

// NewLoginHandler creates the login page. While the setup is pending (there
// are no users), it sends the users to setupURL.
func NewLoginHandler(config *domain.Config, now func() time.Time, setup *SetupHandler, setupURL string) *LoginHandler {
	return &LoginHandler{
		name:          config.Name,
		now:           now,
		template:      utils.ParseTemplates(config.BasePath, config.BaseTemplateFilepath, config.LoginTemplateFilepath),
		sessionTTL:    config.SessionTTL,
		sessionStore:  config.SessionStore,
		userStore:     config.UserStore,
		userBlocked:   config.UserBlockedStore,
		masterKey:     config.MasterKey,
		requireMFA:    config.RequireMFA,
		secureCookies: config.UseSecureCookie,
		home:          config.BasePath + "/",
		setup:         setup,
		setupURL:      setupURL,
	}
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.setup.Pending() {
		http.Redirect(w, r, h.setupURL, http.StatusFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.render(w, loginModel{CSRF: utils.GetCSRFToken(r), Username: loginHint(r)})
	case http.MethodPost:
		h.postHTTP(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *LoginHandler) postHTTP(w http.ResponseWriter, r *http.Request) {
	if !utils.GetCSRFValid(r) {
		h.renderStatus(w, http.StatusBadRequest, loginModel{Username: r.PostFormValue("username"), CSRF: utils.GetCSRFToken(r), FormExpired: true})
		return
	}

	now := h.now()
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")
	model := loginModel{Username: username, CSRF: utils.GetCSRFToken(r)}

	// the block is checked before the password, so a blocked account does not
	// reveal if a password is right. Any username can be blocked, so it does not
	// reveal which users exist either.
	blockKey := "login:" + strings.ToLower(username)
	if h.userBlocked.IsBlocked(blockKey, now) {
		model.TooManyAttempts = true
		h.render(w, model)
		return
	}

	if username == "" || password == "" {
		model.InvalidLogin = true
		h.render(w, model)
		return
	}

	user, err := h.userStore.GetUserByUsernameAndPassword(username, password)
	if err != nil {
		model.TooManyAttempts = h.userBlocked.AddFailedAttempt(blockKey, now)
		model.InvalidLogin = !model.TooManyAttempts
		h.render(w, model)
		return
	}

	h.userBlocked.Reset(blockKey)

	expiresAt := now.Add(h.sessionTTL)
	session, err := h.sessionStore.NewSession(stores.CreateUID(), user, now, expiresAt, h.requireMFA)
	if err != nil {
		model.UnknownError = true
		h.render(w, model)
		return
	}

	if err := utils.SetSessionCookie(w, h.masterKey, session.ID(), expiresAt, h.secureCookies); err != nil {
		model.UnknownError = true
		h.render(w, model)
		return
	}

	http.Redirect(w, r, utils.GetReturnURL(r, h.home), http.StatusFound)
}

// loginHint returns the login_hint parameter (OIDC Core section 3.1.2.1) to prefill the username
func loginHint(r *http.Request) string {
	const maxLength = 256
	hint := r.URL.Query().Get("login_hint")
	if len(hint) > maxLength {
		return ""
	}

	return hint
}

func (h *LoginHandler) render(w http.ResponseWriter, model loginModel) {
	h.renderStatus(w, http.StatusOK, model)
}

func (h *LoginHandler) renderStatus(w http.ResponseWriter, status int, model loginModel) {
	model.Name = h.name
	utils.RenderTemplateStatus(w, status, h.template, model)
}

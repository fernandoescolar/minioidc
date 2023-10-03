package handlers

import (
	"html/template"
	"net/http"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/internal/stores"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type LoginHandler struct {
	name          string
	now           func() time.Time
	templates     []string
	sessionTTL    time.Duration
	sessionStore  domain.SessionStore
	userStore     domain.UserStore
	masterKey     string
	requireMFA    bool
	secureCookies bool
}

var _ http.Handler = (*LoginHandler)(nil)

func NewLoginHandler(config *domain.Config, now func() time.Time) *LoginHandler {
	return &LoginHandler{
		name:          config.Name,
		now:           now,
		templates:     []string{config.BaseTemplateFilepath, config.LoginTemplateFilepath},
		sessionTTL:    config.SessionTTL,
		sessionStore:  config.SessionStore,
		userStore:     config.UserStore,
		masterKey:     config.MasterKey,
		requireMFA:    config.RequireMFA,
		secureCookies: config.UseSecureCookie,
	}
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// show login form
	if r.Method == http.MethodGet {
		h.getHTTP(w, r)
		return
	}

	// handle login form submission
	if r.Method == http.MethodPost {
		h.postHTTP(w, r)
		return
	}

	// handle logout
	if r.Method == http.MethodDelete {
		h.deleteHTTP(w, r)
		return
	}

	// not found
	http.NotFound(w, r)
}

func (h *LoginHandler) getHTTP(w http.ResponseWriter, r *http.Request) {
	csrf := utils.GetCSRFToken(r)
	h.renderLoginPage(w, "", false, false, csrf)
}

func (h *LoginHandler) postHTTP(w http.ResponseWriter, r *http.Request) {
	if !utils.GetCSRFValid(r) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	csrf := utils.GetCSRFToken(r)
	returnURL := utils.GetReturnURL(r)
	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := h.userStore.GetUserByUsername(username)
	if err != nil {
		h.renderLoginPage(w, username, true, false, csrf)
		return
	}

	if !user.PasswordIsValid(password) {
		h.renderLoginPage(w, username, true, false, csrf)
		return
	}

	expiresAt := h.now().Add(h.sessionTTL)
	session, err := h.sessionStore.NewSession(stores.CreateUID(), user, expiresAt, h.requireMFA)
	if err != nil {
		h.renderLoginPage(w, username, false, true, csrf)
		return
	}

	// encrypt session ID
	encryptedSessionID, err := cryptography.Encrypts(h.masterKey, session.ID())
	if err != nil {
		h.renderLoginPage(w, username, false, true, csrf)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    encryptedSessionID,
		Expires:  expiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   h.secureCookies,
	})

	w.Header().Set("Location", returnURL)
	w.WriteHeader(http.StatusFound)
}

func (h *LoginHandler) deleteHTTP(w http.ResponseWriter, _ *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Expires:  h.now().Add(-1),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   h.secureCookies,
	})

	w.WriteHeader(http.StatusNoContent)
}

func (h *LoginHandler) renderLoginPage(w http.ResponseWriter, username string, invalidLogin bool, unknownError bool, csrf string) {
	tmpl, err := template.ParseFiles(h.templates...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, struct {
		Name                       string
		Username                   string
		InvalidLogin, UnknownError bool
		CSRF                       string
	}{h.name, username, invalidLogin, unknownError, csrf})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

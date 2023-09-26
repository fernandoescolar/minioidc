package handlers

import (
	"html/template"
	"net/http"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/google/uuid"
)

type LoginHandler struct {
	now              func() time.Time
	templateFilepath string
	sessionTTL       time.Duration
	sessionStore     domain.SessionStore
	userStore        domain.UserStore
}

func NewLoginHandler(config *domain.Config, now func() time.Time) *LoginHandler {
	return &LoginHandler{
		now:              now,
		templateFilepath: config.LoginTemplateFilepath,
		sessionTTL:       config.SessionTTL,
		sessionStore:     config.SessionStore,
		userStore:        config.UserStore,
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

func (h *LoginHandler) getHTTP(w http.ResponseWriter, _ *http.Request) {
	// returnURL := getReturnURL(r)
	// returnURL, _ = url.QueryUnescape(returnURL)

	h.renderLoginPage(w, "", false, false)
}

func (h *LoginHandler) postHTTP(w http.ResponseWriter, r *http.Request) {
	returnURL := getReturnURL(r)
	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := h.userStore.GetUserByUsername(username)
	if err != nil {
		h.renderLoginPage(w, username, true, false)
		return
	}

	if !user.PasswordIsValid(password) {
		h.renderLoginPage(w, username, true, false)
		return
	}

	expiresAt := h.now().Add(h.sessionTTL)
	session, err := h.sessionStore.NewSession(uuid.New().String(), user, expiresAt)
	if err != nil {
		h.renderLoginPage(w, username, false, true)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    session.ID(),
		Expires:  expiresAt,
		HttpOnly: true,
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
	})

	w.WriteHeader(http.StatusNoContent)
}

func (h *LoginHandler) renderLoginPage(w http.ResponseWriter, username string, invalidLogin bool, unknownError bool) {
	tmpl, err := template.ParseFiles(h.templateFilepath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, struct {
		Username                   string
		InvalidLogin, UnknownError bool
	}{username, invalidLogin, unknownError})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func getReturnURL(req *http.Request) string {
	returnURL := req.URL.Query().Get("return_url")
	if returnURL == "" {
		returnURL = "/"
	}

	return returnURL
}

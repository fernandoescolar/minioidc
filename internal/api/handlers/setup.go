package handlers

import (
	"crypto/subtle"
	"html/template"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/internal/stores"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/google/uuid"
)

// setupCodeBytes are the random bytes of the generated setup codes (80 bits,
// 16 base32 characters)
const setupCodeBytes = 10

// SetupHandler is the onboarding of a new server: when the users are stored
// in SQLite and there are none, it creates the first administrator. Only who
// runs the server can do it: the setup code is written in the log.
type SetupHandler struct {
	name          string
	now           func() time.Time
	template      *template.Template
	users         domain.UserAdminStore
	mfaStore      domain.MFACodeStore
	sessionStore  domain.SessionStore
	sessionTTL    time.Duration
	masterKey     string
	requireMFA    bool
	secureCookies bool
	adminGroup    string
	adminURL      string
	issuer        string
	home          string
	loginURL      string
	welcomeURL    string
	code          string

	mu      sync.Mutex
	pending atomic.Bool
}

type setupModel struct {
	Name string
	CSRF string

	// the form of the administrator
	Code         string
	CodeFromLink bool
	Username     string
	DisplayName  string
	Email        string

	InvalidCode      bool
	MissingUsername  bool
	PasswordMismatch bool
	WeakPassword     bool
	UnknownError     bool
	FormExpired      bool

	// the welcome page, once the administrator is created
	Ready        bool
	Issuer       string
	DiscoveryURL string
	AdminURL     string
	HasMFA       bool
}

var _ http.Handler = (*SetupHandler)(nil)

// NewSetupHandler starts the onboarding if the users can be managed and there
// are none. setupURL is the absolute URL of the setup page, for the log.
func NewSetupHandler(config *domain.Config, now func() time.Time, setupURL, loginURL, welcomeURL string) *SetupHandler {
	h := &SetupHandler{
		name:          config.Name,
		now:           now,
		template:      utils.ParseTemplates(config.BasePath, config.BaseTemplateFilepath, config.SetupTemplateFilepath),
		mfaStore:      config.MFACodeStore,
		sessionStore:  config.SessionStore,
		sessionTTL:    config.SessionTTL,
		masterKey:     config.MasterKey,
		requireMFA:    config.RequireMFA,
		secureCookies: config.UseSecureCookie,
		adminGroup:    config.AdminGroup,
		issuer:        config.Issuer,
		home:          config.BasePath + "/",
		loginURL:      loginURL,
		welcomeURL:    welcomeURL,
	}
	if config.AdminEnabled {
		h.adminURL = config.BasePath + "/admin/"
	}

	users, ok := config.UserStore.(domain.UserAdminStore)
	if !ok {
		return h
	}

	existing, err := users.ListUsers()
	if err != nil {
		log.Printf("Setup: cannot list the users: %v", err)
		return h
	}
	if len(existing) > 0 {
		return h
	}

	h.users = users
	h.code = config.SetupCode
	if h.code != "" {
		log.Printf("There are no users yet: create the administrator at %s with the configured setup code", setupURL)
	} else {
		code, err := cryptography.RandomPassword(setupCodeBytes)
		if err != nil {
			log.Printf("Setup: cannot create the setup code: %v", err)
			return h
		}

		h.code = formatSetupCode(code)
		log.Printf("There are no users yet: create the administrator at %s?code=%s (setup code: %s)", setupURL, h.code, h.code)
	}
	h.pending.Store(true)

	return h
}

// Pending is true while the first administrator has not been created
func (h *SetupHandler) Pending() bool {
	return h != nil && h.pending.Load()
}

func (h *SetupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.Pending() {
		http.Redirect(w, r, h.home, http.StatusFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		code := r.URL.Query().Get("code")
		h.render(w, http.StatusOK, setupModel{CSRF: utils.GetCSRFToken(r), Code: code, CodeFromLink: code != ""})
	case http.MethodPost:
		h.postHTTP(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *SetupHandler) postHTTP(w http.ResponseWriter, r *http.Request) {
	model := setupModel{
		CSRF:         utils.GetCSRFToken(r),
		Code:         r.PostFormValue("code"),
		CodeFromLink: r.PostFormValue("code_from_link") != "",
		Username:     strings.TrimSpace(r.PostFormValue("username")),
		DisplayName:  strings.TrimSpace(r.PostFormValue("name")),
		Email:        strings.TrimSpace(r.PostFormValue("email")),
	}
	if !utils.GetCSRFValid(r) {
		model.FormExpired = true
		h.render(w, http.StatusBadRequest, model)
		return
	}

	password := r.PostFormValue("password")
	switch {
	case !h.validCode(model.Code):
		// the code of the link was wrong: let the user type it
		model.InvalidCode, model.CodeFromLink = true, false
	case model.Username == "":
		model.MissingUsername = true
	case len(password) < minPasswordLength:
		model.WeakPassword = true
	case password != r.PostFormValue("confirm_password"):
		model.PasswordMismatch = true
	}
	if model.InvalidCode || model.MissingUsername || model.WeakPassword || model.PasswordMismatch {
		h.render(w, http.StatusOK, model)
		return
	}

	passwordHash, err := cryptography.HashPassword(password)
	if err != nil {
		model.UnknownError = true
		h.render(w, http.StatusOK, model)
		return
	}

	user, created := h.createAdministrator(domain.UserData{
		Subject:           uuid.NewString(),
		PreferredUsername: model.Username,
		Name:              model.DisplayName,
		Email:             model.Email,
		Groups:            []string{h.adminGroup},
		PasswordHash:      passwordHash,
	})
	if !created {
		// another request has created the administrator
		http.Redirect(w, r, h.home, http.StatusFound)
		return
	}
	if user == nil {
		model.UnknownError = true
		h.render(w, http.StatusOK, model)
		return
	}

	// the administrator is signed in, as after the login
	now := h.now()
	expiresAt := now.Add(h.sessionTTL)
	session, err := h.sessionStore.NewSession(stores.CreateUID(), user, now, expiresAt, h.requireMFA)
	if err == nil {
		err = utils.SetSessionCookie(w, h.masterKey, session.ID(), expiresAt, h.secureCookies)
	}
	if err != nil {
		log.Printf("Setup: cannot sign in the administrator: %v", err)
		http.Redirect(w, r, h.loginURL, http.StatusFound)
		return
	}

	http.Redirect(w, r, h.welcomeURL, http.StatusFound)
}

// createAdministrator creates the user if the setup is still pending. created
// is false if it was not; user is nil if the store failed.
func (h *SetupHandler) createAdministrator(data domain.UserData) (user domain.User, created bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.pending.Load() {
		return nil, false
	}

	user, err := h.users.NewUser(data)
	if err != nil {
		log.Printf("Setup: cannot create the administrator: %v", err)
		return nil, true
	}

	h.pending.Store(false)
	log.Printf("Setup: the administrator %s has been created", data.PreferredUsername)
	return user, true
}

func (h *SetupHandler) validCode(code string) bool {
	expected := normalizeSetupCode(h.code)
	return expected != "" && subtle.ConstantTimeCompare([]byte(normalizeSetupCode(code)), []byte(expected)) == 1
}

// Welcome is the page after the setup: the next steps of the administrators.
// It requires a session.
func (h *SetupHandler) Welcome() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := utils.GetSession(r)
		if r.Method != http.MethodGet || session == nil {
			http.NotFound(w, r)
			return
		}

		user := session.User()
		if !user.InGroup(h.adminGroup) {
			http.Redirect(w, r, h.home, http.StatusFound)
			return
		}

		hasMFA, _ := h.mfaStore.UserHasMFACodes(user.ID())
		h.render(w, http.StatusOK, setupModel{
			Ready:        true,
			Username:     user.Data().PreferredUsername,
			Issuer:       h.issuer,
			DiscoveryURL: strings.TrimSuffix(h.issuer, "/") + "/.well-known/openid-configuration",
			AdminURL:     h.adminURL,
			HasMFA:       hasMFA,
		})
	})
}

func (h *SetupHandler) render(w http.ResponseWriter, status int, model setupModel) {
	model.Name = h.name
	utils.RenderTemplateStatus(w, status, h.template, model)
}

// formatSetupCode groups the code in blocks of 4 characters: ABCD-EFGH-…
func formatSetupCode(code string) string {
	var b strings.Builder
	for i, c := range code {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(c)
	}

	return b.String()
}

// normalizeSetupCode ignores the case, the spaces and the dashes
func normalizeSetupCode(code string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		return r
	}, strings.ToUpper(strings.TrimSpace(code)))
}

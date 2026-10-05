package handlers

import (
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/internal/credentials"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// ResetPasswordHandler is the page of the password reset links: an
// administrator creates the link and gives it to the user, that chooses a new
// password. The link can be used once, and the sessions of the user are closed.
type ResetPasswordHandler struct {
	name         string
	now          func() time.Time
	template     *template.Template
	resets       domain.PasswordResetStore
	userStore    domain.UserStore
	userStates   domain.UserStateStore
	sessionStore domain.SessionStore
	userBlocked  domain.UserBlockedStore
	events       *domain.Recorder
	loginURL     string
}

type resetPasswordModel struct {
	Name             string
	CSRF             string
	Token            string
	Username         string
	InvalidLink      bool
	PasswordMismatch bool
	WeakPassword     bool
	UnknownError     bool
	FormExpired      bool
}

var _ http.Handler = (*ResetPasswordHandler)(nil)

func NewResetPasswordHandler(config *domain.Config, now func() time.Time, loginURL string) *ResetPasswordHandler {
	return &ResetPasswordHandler{
		name:         config.Name,
		now:          now,
		template:     utils.ParseTemplates(config.BasePath, config.BaseTemplateFilepath, config.ResetPasswordTemplateFilepath),
		resets:       config.PasswordResetStore,
		userStore:    config.UserStore,
		userStates:   config.UserStateStore,
		sessionStore: config.SessionStore,
		userBlocked:  config.UserBlockedStore,
		events:       config.Events,
		loginURL:     loginURL,
	}
}

func (h *ResetPasswordHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// the token is a credential: it must not leak in the Referer header
	w.Header().Set("Referrer-Policy", "no-referrer")

	switch r.Method {
	case http.MethodGet:
		token := r.URL.Query().Get("token")
		model := resetPasswordModel{CSRF: utils.GetCSRFToken(r), Token: token}
		if user, ok := h.user(token, h.resets.CheckPasswordReset); ok {
			model.Username = user.Data().PreferredUsername
		} else {
			model.InvalidLink = true
		}
		h.render(w, model)
	case http.MethodPost:
		h.postHTTP(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *ResetPasswordHandler) postHTTP(w http.ResponseWriter, r *http.Request) {
	token := r.PostFormValue("token")
	model := resetPasswordModel{CSRF: utils.GetCSRFToken(r), Token: token}
	user, ok := h.user(token, h.resets.CheckPasswordReset)
	if !ok {
		model.InvalidLink = true
		h.render(w, model)
		return
	}
	model.Username = user.Data().PreferredUsername

	if !utils.GetCSRFValid(r) {
		model.FormExpired = true
		h.render(w, model)
		return
	}

	password := r.PostFormValue("new_password")
	switch {
	case len(password) < minPasswordLength:
		model.WeakPassword = true
	case password != r.PostFormValue("confirm_password"):
		model.PasswordMismatch = true
	}
	if model.WeakPassword || model.PasswordMismatch {
		h.render(w, model)
		return
	}

	updater, ok := h.userStore.(domain.PasswordUpdater)
	if !ok {
		model.UnknownError = true
		h.render(w, model)
		return
	}

	// the link is used now: two requests cannot use it
	if _, ok := h.user(token, h.resets.TakePasswordReset); !ok {
		h.events.RecordUser(r, domain.EventPasswordReset, domain.ResultFailure, user, "the link has already been used")
		model.InvalidLink = true
		h.render(w, model)
		return
	}

	hash, err := cryptography.HashPassword(password)
	if err == nil {
		err = updater.UpdatePassword(user.ID(), hash)
	}
	if err != nil {
		log.Printf("Reset password: %v", err)
		model.UnknownError = true
		h.render(w, model)
		return
	}

	if state, err := h.userStates.GetUserState(user.ID()); err == nil && state.PasswordChangeRequired {
		state.PasswordChangeRequired = false
		_ = h.userStates.SaveUserState(state)
	}
	h.sessionStore.DeleteUserSessions(user.ID())
	h.userBlocked.Reset(credentials.LoginBlockKey(user.Data().PreferredUsername))
	log.Printf("Reset password: the password of %s has been changed with a reset link", user.Data().PreferredUsername)
	h.events.RecordUser(r, domain.EventPasswordReset, domain.ResultSuccess, user, "with a reset link")

	http.Redirect(w, r, h.loginURL+"?reset=1", http.StatusSeeOther)
}

// user returns the user of the token: lookup checks or takes the reset
func (h *ResetPasswordHandler) user(token string, lookup func(string, time.Time) (string, error)) (domain.User, bool) {
	if token == "" {
		return nil, false
	}

	userID, err := lookup(cryptography.SHA256(token), h.now())
	if err != nil {
		return nil, false
	}

	user, err := h.userStore.GetUserByID(userID)
	return user, err == nil
}

func (h *ResetPasswordHandler) render(w http.ResponseWriter, model resetPasswordModel) {
	model.Name = h.name
	utils.RenderTemplate(w, h.template, model)
}

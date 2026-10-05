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

const minPasswordLength = 8

// ProfilePasswordHandler lets the users change their password
type ProfilePasswordHandler struct {
	name         string
	now          func() time.Time
	template     *template.Template
	userStore    domain.UserStore
	sessionStore domain.SessionStore
	userBlocked  domain.UserBlockedStore
	events       *domain.Recorder
	userStates   domain.UserStateStore
	home         string
}

type profilePasswordModel struct {
	Name             string
	CSRF             string
	Success          bool
	InvalidPassword  bool
	PasswordMismatch bool
	WeakPassword     bool
	TooManyAttempts  bool
	UnknownError     bool
	FormExpired      bool
	SamePassword     bool
	// Required is true with a temporary password: the user must change it
	Required bool
}

var _ http.Handler = (*ProfilePasswordHandler)(nil)

func NewProfilePasswordHandler(config *domain.Config, now func() time.Time) *ProfilePasswordHandler {
	return &ProfilePasswordHandler{
		name:         config.Name,
		now:          now,
		template:     utils.ParseTemplates(config.BasePath, config.BaseTemplateFilepath, config.ProfilePasswordTemplateFilepath),
		userStore:    config.UserStore,
		sessionStore: config.SessionStore,
		userBlocked:  config.UserBlockedStore,
		events:       config.Events,
		userStates:   config.UserStateStore,
		home:         config.BasePath + "/",
	}
}

func (h *ProfilePasswordHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session := utils.GetSession(r)
	if session == nil {
		utils.InternalServerError(w, "Failed to get session")
		return
	}

	updater, ok := h.userStore.(domain.PasswordUpdater)
	if !ok || !canChangePassword(h.userStore, session.User()) {
		http.Error(w, "The password of this user cannot be changed here", http.StatusForbidden)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.render(w, session, profilePasswordModel{CSRF: utils.GetCSRFToken(r)})
	case http.MethodPost:
		h.postHTTP(w, r, session, updater)
	default:
		http.NotFound(w, r)
	}
}

func (h *ProfilePasswordHandler) postHTTP(w http.ResponseWriter, r *http.Request, session domain.Session, updater domain.PasswordUpdater) {
	if !utils.GetCSRFValid(r) {
		h.render(w, session, profilePasswordModel{CSRF: utils.GetCSRFToken(r), FormExpired: true})
		return
	}

	model := profilePasswordModel{CSRF: utils.GetCSRFToken(r)}
	now := h.now()
	user := session.User()

	// a wrong current password counts as a failed login
	blockKey := credentials.LoginBlockKey(user.Data().PreferredUsername)
	if h.userBlocked.IsBlocked(blockKey, now) {
		model.TooManyAttempts = true
		h.render(w, session, model)
		return
	}

	if !user.PasswordIsValid(r.PostFormValue("current_password")) {
		h.events.RecordUser(r, domain.EventPasswordChange, domain.ResultFailure, user, "invalid current password")
		model.TooManyAttempts = h.userBlocked.AddFailedAttempt(blockKey, now)
		model.InvalidPassword = !model.TooManyAttempts
		h.render(w, session, model)
		return
	}

	newPassword := r.PostFormValue("new_password")
	switch {
	case newPassword != r.PostFormValue("confirm_password"):
		model.PasswordMismatch = true
	case len(newPassword) < minPasswordLength:
		model.WeakPassword = true
	case newPassword == r.PostFormValue("current_password"):
		model.SamePassword = true
	}
	if model.PasswordMismatch || model.WeakPassword || model.SamePassword {
		h.render(w, session, model)
		return
	}

	hash, err := cryptography.HashPassword(newPassword)
	if err == nil {
		err = updater.UpdatePassword(user.ID(), hash)
	}
	if err != nil {
		log.Printf("Error updating password: %v", err)
		model.UnknownError = true
		h.render(w, session, model)
		return
	}

	h.userBlocked.Reset(blockKey)
	h.closeOtherSessions(session, now)
	h.events.RecordUser(r, domain.EventPasswordChange, domain.ResultSuccess, user, "")

	// the temporary password has been changed: continue where the user was going
	if state, err := h.userStates.GetUserState(user.ID()); err == nil && state.PasswordChangeRequired {
		state.PasswordChangeRequired = false
		if err := h.userStates.SaveUserState(state); err != nil {
			log.Printf("Error saving the user state: %v", err)
		}

		http.Redirect(w, r, utils.GetReturnURL(r, h.home), http.StatusSeeOther)
		return
	}

	model.Success = true
	h.render(w, session, model)
}

// closeOtherSessions logs out the other sessions of the user: if the password
// was stolen, the attacker loses the access
func (h *ProfilePasswordHandler) closeOtherSessions(current domain.Session, now time.Time) {
	sessions, err := h.sessionStore.ListUserSessions(current.User().ID(), now)
	if err != nil {
		log.Printf("Error listing sessions: %v", err)
		return
	}

	for _, s := range sessions {
		if s.ID() != current.ID() {
			_ = h.sessionStore.DeleteSession(s.ID())
		}
	}
}

func (h *ProfilePasswordHandler) render(w http.ResponseWriter, session domain.Session, model profilePasswordModel) {
	state, _ := h.userStates.GetUserState(session.User().ID())
	model.Required = state.PasswordChangeRequired
	model.Name = h.name
	utils.RenderTemplate(w, h.template, model)
}

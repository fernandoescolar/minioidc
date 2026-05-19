package handlers

import (
	"html/template"
	"log"
	"net/http"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type ProfilePasswordHandler struct {
	name      string
	templates []string
	userStore domain.UserStore
}

type profilePasswordModel struct {
	Name             string
	CSRF             string
	Success          bool
	InvalidPassword  bool
	PasswordMismatch bool
	UnknownError     bool
}

var _ http.Handler = (*ProfilePasswordHandler)(nil)

func NewProfilePasswordHandler(config *domain.Config) *ProfilePasswordHandler {
	return &ProfilePasswordHandler{
		name:      config.Name,
		templates: []string{config.BaseTemplateFilepath, config.ProfilePasswordTemplateFilepath},
		userStore: config.UserStore,
	}
}

func (h *ProfilePasswordHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		h.getHTTP(w, r)
		return
	}

	if r.Method == http.MethodPost {
		h.postHTTP(w, r)
		return
	}

	http.NotFound(w, r)
}

func (h *ProfilePasswordHandler) getHTTP(w http.ResponseWriter, r *http.Request) {
	csrf := utils.GetCSRFToken(r)
	h.render(w, profilePasswordModel{Name: h.name, CSRF: csrf})
}

func (h *ProfilePasswordHandler) postHTTP(w http.ResponseWriter, r *http.Request) {
	if !utils.GetCSRFValid(r) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	session := utils.GetSession(r)
	if session == nil {
		utils.InternalServerError(w, "Failed to get session")
		return
	}

	csrf := utils.GetCSRFToken(r)

	r.ParseForm()
	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	// Validate current password
	if !session.User().PasswordIsValid(currentPassword) {
		h.render(w, profilePasswordModel{Name: h.name, CSRF: csrf, InvalidPassword: true})
		return
	}

	// Validate new passwords match
	if newPassword != confirmPassword {
		h.render(w, profilePasswordModel{Name: h.name, CSRF: csrf, PasswordMismatch: true})
		return
	}

	// Hash and store new password
	hash, err := cryptography.HashPassword(newPassword)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		h.render(w, profilePasswordModel{Name: h.name, CSRF: csrf, UnknownError: true})
		return
	}

	if err := h.userStore.UpdatePassword(session.User().ID(), hash); err != nil {
		log.Printf("Error updating password: %v", err)
		h.render(w, profilePasswordModel{Name: h.name, CSRF: csrf, UnknownError: true})
		return
	}

	h.render(w, profilePasswordModel{Name: h.name, CSRF: csrf, Success: true})
}

func (h *ProfilePasswordHandler) render(w http.ResponseWriter, model profilePasswordModel) {
	tmpl, err := template.ParseFiles(h.templates...)
	if err != nil {
		utils.InternalServerError(w, "Failed to parse template")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, model); err != nil {
		log.Printf("Error rendering profile_password template: %v", err)
	}
}

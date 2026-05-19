package handlers

import (
	"html/template"
	"net/http"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type ProfileHandler struct {
	name      string
	templates []string
}

type profileModel struct {
	Name     string
	Username string
	CSRF     string
}

var _ http.Handler = (*ProfileHandler)(nil)

func NewProfileHandler(config *domain.Config) *ProfileHandler {
	return &ProfileHandler{
		name:      config.Name,
		templates: []string{config.BaseTemplateFilepath, config.ProfileTemplateFilepath},
	}
}

func (h *ProfileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	session := utils.GetSession(r)
	if session == nil {
		utils.InternalServerError(w, "Failed to get session")
		return
	}

	csrf := utils.GetCSRFToken(r)
	model := profileModel{
		Name:     h.name,
		Username: session.User().Username(),
		CSRF:     csrf,
	}

	tmpl, err := template.ParseFiles(h.templates...)
	if err != nil {
		utils.InternalServerError(w, "Failed to parse template")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, model); err != nil {
		utils.InternalServerError(w, "Failed to render template")
	}
}

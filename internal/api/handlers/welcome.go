package handlers

import (
	"html/template"
	"net/http"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// HomeHandler sends the home page to the profile of the user, and answers the
// unknown paths with a not found page
type HomeHandler struct {
	home       string
	profileURL string
	errors     *ErrorPage
}

var _ http.Handler = (*HomeHandler)(nil)

func NewHomeHandler(config *domain.Config, profileURL string) *HomeHandler {
	return &HomeHandler{
		home:       config.BasePath + "/",
		profileURL: profileURL,
		errors:     NewErrorPage(config),
	}
}

func (h *HomeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == h.home {
		http.Redirect(w, r, h.profileURL, http.StatusFound)
		return
	}

	h.errors.Render(w, http.StatusNotFound, "Page not found", "The page you are looking for does not exist.")
}

// ErrorPage renders the error pages with the design of the other pages
type ErrorPage struct {
	name     string
	template *template.Template
}

type errorModel struct {
	Name    string
	Status  int
	Title   string
	Message string
}

func NewErrorPage(config *domain.Config) *ErrorPage {
	return &ErrorPage{
		name:     config.Name,
		template: utils.ParseTemplates(config.BasePath, config.BaseTemplateFilepath, config.ErrorTemplateFilepath),
	}
}

func (p *ErrorPage) Render(w http.ResponseWriter, status int, title, message string) {
	utils.RenderTemplateStatus(w, status, p.template, errorModel{Name: p.name, Status: status, Title: title, Message: message})
}

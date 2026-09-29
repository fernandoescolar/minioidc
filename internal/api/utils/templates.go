package utils

import (
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"strings"
)

// ParseTemplates parses the templates once. It panics if they are not valid,
// so a wrong configuration fails on start up. The templates can use
// {{ basePath }} to build the URLs (e.g. {{ basePath }}/static/styles.css).
func ParseTemplates(basePath string, filenames ...string) *template.Template {
	if len(filenames) == 0 {
		panic("no templates")
	}

	funcs := template.FuncMap{
		"basePath":         func() string { return basePath },
		"initial":          initial,
		"scopeDescription": scopeDescription,
		"inc":              func(i int) int { return i + 1 },
	}
	return template.Must(template.New(filepath.Base(filenames[0])).Funcs(funcs).ParseFiles(filenames...))
}

// RenderTemplate renders an HTML template
func RenderTemplate(w http.ResponseWriter, tmpl *template.Template, data interface{}) {
	RenderTemplateStatus(w, http.StatusOK, tmpl, data)
}

// RenderTemplateStatus renders an HTML template with a status code
func RenderTemplateStatus(w http.ResponseWriter, status int, tmpl *template.Template, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	NoCache(w)
	w.WriteHeader(status)
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Error rendering template: %v", err)
	}
}

// initial is the first letter of the name (the brand mark of the pages)
func initial(name string) string {
	for _, r := range strings.TrimSpace(name) {
		return strings.ToUpper(string(r))
	}

	return "?"
}

var scopeDescriptions = map[string]string{
	"openid":         "Sign you in",
	"profile":        "See your name and username",
	"email":          "See your email address",
	"address":        "See your address",
	"phone":          "See your phone number",
	"groups":         "See your groups",
	"offline_access": "Keep the access while you are away",
}

// scopeDescription describes a scope to the users (e.g. in the device flow)
func scopeDescription(scope string) string {
	if description, ok := scopeDescriptions[scope]; ok {
		return description
	}

	return scope
}

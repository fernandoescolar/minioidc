package utils

import (
	"html/template"
	"log"
	"net/http"
	"path/filepath"
)

// ParseTemplates parses the templates once. It panics if they are not valid,
// so a wrong configuration fails on start up. The templates can use
// {{ basePath }} to build the URLs (e.g. {{ basePath }}/static/styles.css).
func ParseTemplates(basePath string, filenames ...string) *template.Template {
	if len(filenames) == 0 {
		panic("no templates")
	}

	funcs := template.FuncMap{"basePath": func() string { return basePath }}
	return template.Must(template.New(filepath.Base(filenames[0])).Funcs(funcs).ParseFiles(filenames...))
}

// RenderTemplate renders an HTML template
func RenderTemplate(w http.ResponseWriter, tmpl *template.Template, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	NoCache(w)
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Error rendering template: %v", err)
	}
}

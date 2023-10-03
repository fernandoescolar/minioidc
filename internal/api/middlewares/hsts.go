package middlewares

import (
	"net/http"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type HSTS struct {
	active bool
}

var _ domain.Middleware = (*HSTS)(nil)

func NewHSTS(config *domain.Config) *CSP {
	return &CSP{active: config.UseHSTS}
}

func (m *HSTS) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if r.URL.Scheme != "https" {
		http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
		return
	}

	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

	next(w, r)
}

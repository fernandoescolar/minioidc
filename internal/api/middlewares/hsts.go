package middlewares

import (
	"net/http"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type HSTS struct {
	active bool
}

var _ domain.Middleware = (*HSTS)(nil)

func NewHSTS(config *domain.Config) *HSTS {
	return &HSTS{active: config.UseHSTS}
}

func (m *HSTS) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if !m.active {
		next(w, r)
		return
	}

	// r.URL.Scheme is set by the ForwardedHeaders middleware behind a proxy
	if r.TLS == nil && r.URL.Scheme != "https" {
		http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
		return
	}

	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

	next(w, r)
}

package middlewares

import (
	"net/http"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type CSP struct {
	active bool
}

var _ domain.Middleware = (*CSP)(nil)

func NewCSP(config *domain.Config) *CSP {
	return &CSP{active: config.UseCSP}
}

func (m *CSP) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; media-src 'self'; object-src 'none'; frame-src 'none';frame-ancestors 'none';base-uri 'self'") //;form-action 'self';")
	next(w, r)
}

package middlewares

import (
	"net/http"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// There are no inline scripts (the QR codes read their data from an attribute),
// so script-src does not allow 'unsafe-inline'.
// form-action is not set on purpose: Chrome applies it to the redirects that
// follow a form submission (login -> authorize -> client redirect_uri).
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; media-src 'self'; object-src 'none'; frame-src 'none'; frame-ancestors 'none'; base-uri 'self'"

type CSP struct {
	active bool
}

var _ domain.Middleware = (*CSP)(nil)

func NewCSP(config *domain.Config) *CSP {
	return &CSP{active: config.UseCSP}
}

func (m *CSP) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if m.active {
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
	}

	next(w, r)
}

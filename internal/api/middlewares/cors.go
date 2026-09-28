package middlewares

import (
	"net/http"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// CORS allows browser clients (SPAs) to call the endpoints that do not use
// cookies: token, userinfo, revocation, discovery and JWKS. Any origin is
// allowed because the requests are authenticated with tokens, never with
// cookies (credentials are not allowed).
type CORS struct {
	paths map[string]bool
}

var _ domain.Middleware = (*CORS)(nil)

func NewCORS(paths []string) *CORS {
	m := &CORS{paths: map[string]bool{}}
	for _, p := range paths {
		m.paths[p] = true
	}

	return m
}

func (m *CORS) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if !m.paths[r.URL.Path] || r.Header.Get("Origin") == "" {
		next(w, r)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")

	// preflight request
	if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Max-Age", "86400")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate")
	next(w, r)
}

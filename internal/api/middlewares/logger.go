package middlewares

import (
	"log"
	"net/http"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type Logger struct {
}

var _ domain.Middleware = (*Logger)(nil)

func NewLogger() *Logger {
	return &Logger{}
}

func (m *Logger) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	log.Printf("Request: %s %s", r.Method, r.URL.Path)
	next(w, r)
}

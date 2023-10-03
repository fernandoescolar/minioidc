package middlewares

import (
	"log"
	"net/http"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type Logger struct {
	active bool
}

var _ domain.Middleware = (*Logger)(nil)

func NewLogger(config *domain.Config) *Logger {
	return &Logger{
		active: config.LogRequests,
	}
}

func (m *Logger) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if !m.active {
		next(w, r)
		return
	}

	log.Printf("Request: %s %s", r.Method, r.URL.Path)
	ww := newStatusWriter(w)
	next(ww, r)
	log.Printf("Response: %s %s %d", r.Method, r.URL.Path, ww.StatusCode())
}

type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

var _ http.ResponseWriter = (*statusResponseWriter)(nil)

func newStatusWriter(w http.ResponseWriter) *statusResponseWriter {
	return &statusResponseWriter{
		ResponseWriter: w,
		status:         http.StatusOK,
	}
}

func (w *statusResponseWriter) StatusCode() int {
	return w.status
}

func (w *statusResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

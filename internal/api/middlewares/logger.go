package middlewares

import (
	"log"
	"net/http"
)

type Logger struct {
}

func NewLogger() *Logger {
	return &Logger{}
}

func (l *Logger) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	log.Printf("Request: %s %s", r.Method, r.URL.Path)
	next(w, r)
}

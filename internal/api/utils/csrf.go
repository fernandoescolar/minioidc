package utils

import (
	"context"
	"net/http"
)

const csrfValidKey contextKey = "csrf_valid"
const csrfTokenKey contextKey = "csrf_token"

func SetCSRFValid(r *http.Request, v bool) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), csrfValidKey, v))
}

func GetCSRFValid(r *http.Request) bool {
	valid, _ := r.Context().Value(csrfValidKey).(bool)
	return valid
}

func SetCSRFToken(r *http.Request, token string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), csrfTokenKey, token))
}

func GetCSRFToken(r *http.Request) string {
	token, _ := r.Context().Value(csrfTokenKey).(string)
	return token
}

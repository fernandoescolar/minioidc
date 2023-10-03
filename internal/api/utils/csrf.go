package utils

import (
	"context"
	"net/http"
)

const csrfValidKey = "csrf_valid"
const csrfTokenKey = "csrf_token"

func SetCSRFValid(r *http.Request, v bool) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), csrfValidKey, v))
}

func GetCSRFValid(r *http.Request) bool {
	valid := r.Context().Value(csrfValidKey)
	if valid == nil {
		return false
	}

	return valid.(bool)
}

func SetCSRFToken(r *http.Request, token string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), csrfTokenKey, token))
}

func GetCSRFToken(r *http.Request) string {
	token := r.Context().Value(csrfTokenKey)
	if token == nil {
		return ""
	}

	return token.(string)
}

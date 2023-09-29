package utils

import (
	"context"
	"net/http"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

const sessionKey = "session"

func SetSession(r *http.Request, session domain.Session) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), sessionKey, session))
}

func GetSession(r *http.Request) domain.Session {
	session := r.Context().Value(sessionKey)
	if session == nil {
		return nil
	}

	return session.(domain.Session)
}

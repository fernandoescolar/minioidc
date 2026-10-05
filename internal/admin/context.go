package admin

import (
	"context"
	"net/http"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// contextWithAdmin keeps the session of the administrator
func contextWithAdmin(r *http.Request, session domain.Session) context.Context {
	return context.WithValue(r.Context(), adminUserKey, session)
}

func adminFromContext(r *http.Request) domain.User {
	session := adminSessionFromContext(r)
	if session == nil {
		return nil
	}

	return session.User()
}

func adminSessionFromContext(r *http.Request) domain.Session {
	session, _ := r.Context().Value(adminUserKey).(domain.Session)
	return session
}

func sessionIDFromRequest(r *http.Request, masterKey string) string {
	return utils.GetSessionIDFromCookie(r, masterKey)
}

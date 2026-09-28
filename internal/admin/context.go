package admin

import (
	"context"
	"net/http"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

func contextWithAdmin(r *http.Request, user domain.User) context.Context {
	return context.WithValue(r.Context(), adminUserKey, user)
}

func adminFromContext(r *http.Request) domain.User {
	user, _ := r.Context().Value(adminUserKey).(domain.User)
	return user
}

func sessionIDFromRequest(r *http.Request, masterKey string) string {
	return utils.GetSessionIDFromCookie(r, masterKey)
}

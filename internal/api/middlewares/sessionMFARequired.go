package middlewares

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type SessionMFARequired struct {
	mfaStore       domain.MFACodeStore
	createEndpoint string
	verifyEndpoint string
}

var _ domain.Middleware = (*SessionMFARequired)(nil)

func NewSessionMFARequired(config *domain.Config, createEndpoint, verifyEndpoint string) *SessionMFARequired {
	return &SessionMFARequired{
		mfaStore:       config.MFACodeStore,
		createEndpoint: createEndpoint,
		verifyEndpoint: verifyEndpoint,
	}
}

func (m *SessionMFARequired) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	session := utils.GetSession(r)
	if session != nil {
		if session.MFARequired() && !strings.HasPrefix(r.URL.Path, m.createEndpoint) && !strings.HasPrefix(r.URL.Path, m.verifyEndpoint) {
			hasMFA, err := m.mfaStore.UserHasMFACodes(session.User().ID())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			returnURL := r.URL.String()
			returnURL = url.QueryEscape(returnURL)
			location := fmt.Sprintf("%s?return_url=%s", m.verifyEndpoint, returnURL)
			if !hasMFA {
				location = fmt.Sprintf("%s?return_url=%s", m.createEndpoint, returnURL)
			}

			http.Redirect(w, r, location, http.StatusFound)
			return
		}

	}

	next(w, r)
}

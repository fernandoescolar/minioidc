package middlewares

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type SessionAuthorized struct {
	now              func() time.Time
	masterKey        string
	loginEndpoint    string
	basePath         string
	excludedPrefixes []string
	sessionStore     domain.SessionStore
}

var _ domain.Middleware = (*SessionAuthorized)(nil)

func NewSessionAuthorized(config *domain.Config, now func() time.Time, loginEndpoint string, excludedPrefixes []string) *SessionAuthorized {
	return &SessionAuthorized{
		now:              now,
		masterKey:        config.MasterKey,
		loginEndpoint:    loginEndpoint,
		basePath:         config.BasePath + "/",
		excludedPrefixes: excludedPrefixes,
		sessionStore:     config.SessionStore,
	}
}

func (m *SessionAuthorized) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if m.isExcluded(r) {
		next(w, r)
		return
	}

	session, valid := m.validateSession(r)
	if !valid {
		returnURL := r.URL.String()
		returnURL = url.QueryEscape(returnURL)
		location := fmt.Sprintf("%s?return_url=%s", m.loginEndpoint, returnURL)
		http.Redirect(w, r, location, http.StatusFound)
		return
	}

	r = utils.SetSession(r, session)
	next(w, r)
}

func (m *SessionAuthorized) isExcluded(r *http.Request) bool {
	// only the paths under the issuer are protected
	if !strings.HasPrefix(r.URL.Path, m.basePath) {
		return true
	}

	for _, prefix := range m.excludedPrefixes {
		if strings.HasPrefix(r.URL.Path, prefix) {
			return true
		}
	}
	return false
}

func (m *SessionAuthorized) validateSession(r *http.Request) (domain.Session, bool) {
	sessionID := utils.GetSessionIDFromCookie(r, m.masterKey)
	if sessionID == "" {
		return nil, false
	}

	session, err := m.sessionStore.GetSessionByID(sessionID)
	if session == nil || err != nil {
		return nil, false
	}

	if session.HasExpired(m.now()) {
		return nil, false
	}

	return session, true
}

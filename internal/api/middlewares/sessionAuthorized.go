package middlewares

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type SessionAuthorized struct {
	masterKey        string
	loginEndpoint    string
	excludedPrefixes []string
	sessionStore     domain.SessionStore
}

var _ domain.Middleware = (*SessionAuthorized)(nil)

func NewSessionAuthorized(config *domain.Config, now func() time.Time, loginEndpoint string, excludedPrefixes []string) *SessionAuthorized {
	return &SessionAuthorized{
		masterKey:        config.MasterKey,
		loginEndpoint:    loginEndpoint,
		excludedPrefixes: excludedPrefixes,
		sessionStore:     config.SessionStore,
	}
}

func (m *SessionAuthorized) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	exluded := m.isExcluded(r)
	if exluded {
		next(w, r)
		return
	}

	session, valid := m.validateSession(w, r)
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
	for _, prefix := range m.excludedPrefixes {
		if strings.HasPrefix(r.URL.Path, prefix) {
			return true
		}
	}
	return false
}

func (m *SessionAuthorized) validateSession(w http.ResponseWriter, r *http.Request) (domain.Session, bool) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil, false
	}

	encryptedSessionID := cookie.Value
	if encryptedSessionID == "" {
		return nil, false
	}

	sessionID, err := cryptography.Decrypts(m.masterKey, encryptedSessionID)
	if sessionID == "" || err != nil {
		return nil, false
	}

	session, err := m.sessionStore.GetSessionByID(sessionID)
	if session == nil || err != nil {
		return nil, false
	}

	if session.HasExpired() {
		return nil, false
	}

	return session, true
}

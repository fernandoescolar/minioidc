package middlewares

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type SessionAuthorized struct {
	sessionStore     domain.SessionStore
	masterKey        string
	loginEndpoint    string
	excludedPrefixes []string
}

var _ domain.Middleware = (*SessionAuthorized)(nil)

func NewSessionAuthorized(config *domain.Config, loginEndpoint string, excludedPrefixes []string) *SessionAuthorized {
	return &SessionAuthorized{
		sessionStore:     config.SessionStore,
		masterKey:        config.MasterKey,
		loginEndpoint:    loginEndpoint,
		excludedPrefixes: excludedPrefixes,
	}
}

func (s *SessionAuthorized) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	exluded := s.isExcluded(r)
	if exluded {
		next(w, r)
		return
	}

	session, valid := s.validateSession(w, r)
	if !valid {
		returnURL := r.URL.String()
		returnURL = url.QueryEscape(returnURL)
		location := fmt.Sprintf("%s?return_url=%s", s.loginEndpoint, returnURL)
		http.Redirect(w, r, location, http.StatusFound)
		return
	}

	r = utils.SetSession(r, session)

	next(w, r)
}

func (s *SessionAuthorized) isExcluded(r *http.Request) bool {
	for _, prefix := range s.excludedPrefixes {
		if strings.HasPrefix(r.URL.Path, prefix) {
			return true
		}
	}
	return false
}

func (s *SessionAuthorized) validateSession(w http.ResponseWriter, r *http.Request) (domain.Session, bool) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil, false
	}

	encryptedSessionID := cookie.Value
	if encryptedSessionID == "" {
		return nil, false
	}

	sessionID, err := cryptography.Decrypts(s.masterKey, encryptedSessionID)
	if sessionID == "" || err != nil {
		return nil, false
	}

	session, err := s.sessionStore.GetSessionByID(sessionID)
	if session == nil || err != nil {
		return nil, false
	}

	if session.HasExpired() {
		return nil, false
	}

	return session, true
}

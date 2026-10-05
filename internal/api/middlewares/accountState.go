package middlewares

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// AccountState applies the state of the account to the sessions: the sessions
// of disabled or locked accounts are closed (the administrators close them,
// this is a second line), and the users with a temporary password must change
// it before using any page. The logins with a passkey did not use the
// password, so they do not have to change it.
type AccountState struct {
	now          func() time.Time
	states       domain.UserStateStore
	sessionStore domain.SessionStore
	loginURL     string
	passwordURL  string
	allowed      []string
}

var _ domain.Middleware = (*AccountState)(nil)

// NewAccountState creates the middleware. allowed are the paths that can be
// used before changing the password (e.g. the MFA pages).
func NewAccountState(config *domain.Config, now func() time.Time, loginURL, passwordURL string, allowed []string) *AccountState {
	return &AccountState{
		now:          now,
		states:       config.UserStateStore,
		sessionStore: config.SessionStore,
		loginURL:     loginURL,
		passwordURL:  passwordURL,
		allowed:      append([]string{passwordURL}, allowed...),
	}
}

func (m *AccountState) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	session := utils.GetSession(r)
	if session == nil {
		next(w, r)
		return
	}

	state, err := m.states.GetUserState(session.User().ID())
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	if state.CanSignIn(m.now()) != nil {
		_ = m.sessionStore.DeleteSession(session.ID())
		http.Redirect(w, r, m.loginURL, http.StatusFound)
		return
	}

	if state.PasswordChangeRequired && !session.Passkey() && !m.isAllowed(r.URL.Path) {
		location := m.passwordURL + "?" + url.Values{"return_url": {r.URL.String()}}.Encode()
		http.Redirect(w, r, location, http.StatusFound)
		return
	}

	next(w, r)
}

func (m *AccountState) isAllowed(path string) bool {
	for _, prefix := range m.allowed {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	return false
}

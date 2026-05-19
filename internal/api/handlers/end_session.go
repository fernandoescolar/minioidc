package handlers

import (
	"net/http"
	"net/url"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// EndSessionHandler implements OIDC RP-Initiated Logout (Session Management §5).
type EndSessionHandler struct {
	now           func() time.Time
	masterKey     string
	sessionStore  domain.SessionStore
	secureCookies bool
}

var _ http.Handler = (*EndSessionHandler)(nil)

func NewEndSessionHandler(config *domain.Config, now func() time.Time) *EndSessionHandler {
	return &EndSessionHandler{
		now:           now,
		masterKey:     config.MasterKey,
		sessionStore:  config.SessionStore,
		secureCookies: config.UseSecureCookie,
	}
}

func (h *EndSessionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	postLogoutRedirectURI := r.Form.Get("post_logout_redirect_uri")
	state := r.Form.Get("state")

	// Clear the session if one exists.
	cookie, err := r.Cookie("session")
	if err == nil && cookie.Value != "" {
		sessionID, err := cryptography.Decrypts(h.masterKey, cookie.Value)
		if err == nil && sessionID != "" {
			session, err := h.sessionStore.GetSessionByID(sessionID)
			if err == nil && session != nil {
				h.sessionStore.DeleteUserSessions(session.User().ID())
			}
		}
	}

	// Expire the session cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   h.secureCookies,
	})

	// Redirect to post_logout_redirect_uri with optional state, or fallback to root.
	if postLogoutRedirectURI != "" {
		ru, err := url.Parse(postLogoutRedirectURI)
		if err == nil {
			if state != "" {
				q := ru.Query()
				q.Set("state", state)
				ru.RawQuery = q.Encode()
			}
			http.Redirect(w, r, ru.String(), http.StatusFound)
			return
		}
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

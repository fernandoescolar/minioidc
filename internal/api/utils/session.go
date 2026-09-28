package utils

import (
	"context"
	"net/http"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type contextKey string

const (
	sessionKey        contextKey = "session"
	sessionCookieName            = "session"
)

func SetSession(r *http.Request, session domain.Session) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), sessionKey, session))
}

func GetSession(r *http.Request) domain.Session {
	session, _ := r.Context().Value(sessionKey).(domain.Session)
	return session
}

// SetSessionCookie writes the encrypted session ID cookie. It uses SameSite=Lax
// because the browser must send it when a client redirects to /authorize.
func SetSessionCookie(w http.ResponseWriter, masterKey, sessionID string, expiresAt time.Time, secure bool) error {
	encryptedSessionID, err := cryptography.Encrypts(masterKey, sessionID)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    encryptedSessionID,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
	})

	return nil
}

// ClearSessionCookie removes the session cookie
func ClearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
	})
}

// GetSessionIDFromCookie returns the decrypted session ID or an empty string
func GetSessionIDFromCookie(r *http.Request, masterKey string) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return ""
	}

	sessionID, err := cryptography.Decrypts(masterKey, cookie.Value)
	if err != nil {
		return ""
	}

	return sessionID
}

package middlewares

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type CSRF struct {
	active       bool
	securecookie bool
	masterKey    string
}

var _ domain.Middleware = (*CSRF)(nil)

func NewCSRF(config *domain.Config) *CSRF {
	return &CSRF{
		active:       true,
		securecookie: config.UseSecureCookie,
		masterKey:    config.MasterKey,
	}
}

const (
	csrfCookieName = "csrf_token"
	csrfInputName  = "__csrf"
	csrfTokenLen   = 32
)

func (m *CSRF) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if !m.active {
		next(w, r)
		return
	}

	if r.Method == http.MethodGet {
		// child request in the same page
		if r.Referer() != "" && !strings.HasPrefix(r.Referer(), r.Host) {
			r = m.referrerGetHTTP(w, r)
		} else {
			r = m.getHTTP(w, r)
		}
	}

	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
			r = m.formHTTP(w, r)
		}
	}

	next(w, r)
}

func (m *CSRF) getHTTP(w http.ResponseWriter, r *http.Request) *http.Request {
	csrfToken, err := generateCSRFCookieValue()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return r
	}
	csrfCookie := &http.Cookie{
		Name:     csrfCookieName,
		Value:    csrfToken,
		HttpOnly: true,
		Secure:   m.securecookie,
		Path:     "/",
	}
	http.SetCookie(w, csrfCookie)

	csrfToken, err = m.generateCSRFToken(csrfCookie.Value)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return r
	}

	r = utils.SetCSRFToken(r, csrfToken)
	return r
}

func (m *CSRF) referrerGetHTTP(w http.ResponseWriter, r *http.Request) *http.Request {
	csrfCookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return r
	}

	csrfToken, err := m.generateCSRFToken(csrfCookie.Value)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return r
	}

	return utils.SetCSRFToken(r, csrfToken)
}

func (m *CSRF) formHTTP(w http.ResponseWriter, r *http.Request) *http.Request {
	csrfCookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return r
	}

	r.ParseForm()
	csrfToken := r.FormValue(csrfInputName)
	if csrfToken == "" {
		return r
	}

	r = utils.SetCSRFToken(r, csrfToken)
	if !m.validateCSRFToken(csrfCookie.Value, csrfToken) {
		return r
	}

	return utils.SetCSRFValid(r, true)
}

func (m *CSRF) generateCSRFToken(csrfCookie string) (string, error) {
	csrfToken, err := cryptography.Encrypts(m.masterKey, csrfCookie)
	if err != nil {
		return "", fmt.Errorf("Cannot encryp CSRF token: %w", err)
	}

	return csrfToken, nil
}

func (m *CSRF) validateCSRFToken(csrfCookie string, csrfToken string) bool {
	v, err := cryptography.Decrypts(m.masterKey, csrfToken)
	if err != nil {
		return false
	}

	return csrfCookie == v
}

func generateCSRFCookieValue() (string, error) {
	b := make([]byte, csrfTokenLen)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

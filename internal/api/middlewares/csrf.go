package middlewares

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// CSRF implements the double submit cookie pattern: a random value is stored
// in a cookie and the forms send an encrypted and timestamped copy of it.
type CSRF struct {
	now          func() time.Time
	securecookie bool
	masterKey    string
	ttl          time.Duration
}

var _ domain.Middleware = (*CSRF)(nil)

func NewCSRF(config *domain.Config, now func() time.Time) *CSRF {
	return &CSRF{
		now:          now,
		securecookie: config.UseSecureCookie,
		masterKey:    config.MasterKey,
		ttl:          config.CSRFTTL,
	}
}

const (
	csrfCookieName = "csrf_token"
	csrfInputName  = "__csrf"
	csrfTokenLen   = 32
)

func (m *CSRF) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		r = m.getHTTP(w, r)
	case http.MethodPost, http.MethodPut:
		if isFormRequest(r) {
			r = m.formHTTP(r)
		}
	}

	next(w, r)
}

// getHTTP reuses the cookie of the browser (so requests of other tabs or
// static files do not invalidate the forms) and creates a token for the forms.
func (m *CSRF) getHTTP(w http.ResponseWriter, r *http.Request) *http.Request {
	cookieValue := ""
	if cookie, err := r.Cookie(csrfCookieName); err == nil && len(cookie.Value) >= csrfTokenLen {
		cookieValue = cookie.Value
	}

	if cookieValue == "" {
		value, err := generateCSRFCookieValue()
		if err != nil {
			utils.InternalServerError(w, err.Error())
			return r
		}

		cookieValue = value
		http.SetCookie(w, &http.Cookie{
			Name:     csrfCookieName,
			Value:    cookieValue,
			HttpOnly: true,
			Secure:   m.securecookie,
			SameSite: http.SameSiteLaxMode,
			Path:     "/",
		})
	}

	csrfToken, err := m.generateCSRFToken(cookieValue)
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return r
	}

	return utils.SetCSRFToken(r, csrfToken)
}

func (m *CSRF) formHTTP(r *http.Request) *http.Request {
	csrfCookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return r
	}

	if err := r.ParseForm(); err != nil {
		return r
	}

	csrfToken := r.PostFormValue(csrfInputName)
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
	csrfToken := fmt.Sprintf("%s:%d", csrfCookie, m.now().Unix())
	csrfToken, err := cryptography.Encrypts(m.masterKey, csrfToken)
	if err != nil {
		return "", fmt.Errorf("Cannot encrypt CSRF token: %w", err)
	}

	return csrfToken, nil
}

func (m *CSRF) validateCSRFToken(csrfCookie string, csrfToken string) bool {
	v, err := cryptography.Decrypts(m.masterKey, csrfToken)
	if err != nil {
		return false
	}

	token, unixtime, found := strings.Cut(v, ":")
	if !found {
		return false
	}

	i, err := strconv.ParseInt(unixtime, 10, 64)
	if err != nil {
		return false
	}

	if m.now().Sub(time.Unix(i, 0)) > m.ttl {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(csrfCookie), []byte(token)) == 1
}

func isFormRequest(r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mediaType == "application/x-www-form-urlencoded"
}

func generateCSRFCookieValue() (string, error) {
	b := make([]byte, csrfTokenLen)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

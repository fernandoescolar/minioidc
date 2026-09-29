package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/internal/credentials"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// requestWithPassword implements the resource owner password credentials grant
// (RFC 6749 section 4.3). It is discouraged (RFC 9700 section 2.4), so it must
// be enabled in the configuration and in the client. The users with MFA add
// their TOTP code to the end of the password, and the failed attempts count
// as failed logins.
func (h *TokenHandler) requestWithPassword(w http.ResponseWriter, r *http.Request, client domain.Client) {
	if !assertPresenceInForm([]string{"username", "password"}, w, r) {
		return
	}

	scopes := strings.Fields(r.PostForm.Get("scope"))
	if errCode, description := validateScope(strings.Join(scopes, " ")); len(scopes) > 0 && errCode != "" {
		utils.Error(w, errCode, description, http.StatusBadRequest)
		return
	}

	now := h.now()
	user, mfaVerified, err := h.credentials.Authenticate(r.PostForm.Get("username"), r.PostForm.Get("password"), now)
	if errors.Is(err, credentials.ErrBlocked) {
		utils.Error(w, utils.InvalidGrant, "Too many failed attempts. Try it again later", http.StatusBadRequest)
		return
	}
	if err != nil {
		utils.Error(w, utils.InvalidGrant, "Invalid username or password", http.StatusBadRequest)
		return
	}

	h.issueForUser(w, client, user, scopes, now, mfaVerified, true)
}

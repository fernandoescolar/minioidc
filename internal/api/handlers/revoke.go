package handlers

import (
	"net/http"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// RevokeHandler implements RFC 7009 token revocation for refresh tokens.
// Access tokens are short lived JWTs and they are revoked when the session ends.
type RevokeHandler struct {
	grantStore    domain.GrantStore
	validator     *accessTokenValidator
	authenticator ClientAuthenticator
	endpointURL   string
}

var _ http.Handler = (*RevokeHandler)(nil)

func NewRevokeHandler(config *domain.Config, now func() time.Time, authenticator ClientAuthenticator, endpointURL string) *RevokeHandler {
	return &RevokeHandler{
		grantStore:    config.GrantStore,
		validator:     newAccessTokenValidator(config, now),
		authenticator: authenticator,
		endpointURL:   endpointURL,
	}
}

func (h *RevokeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.Error(w, utils.InvalidRequest, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		utils.Error(w, utils.InvalidRequest, "Invalid form", http.StatusBadRequest)
		return
	}

	client, ok := authenticateClient(h.authenticator, h.endpointURL, w, r)
	if !ok {
		return
	}

	if !assertPresenceInForm([]string{"token"}, w, r) {
		return
	}

	token := r.PostForm.Get("token")

	// the access tokens are short lived JWTs: they cannot be revoked one by
	// one (they are revoked when their session is closed)
	if _, _, err := h.validator.validate(token); err == nil {
		utils.Error(w, "unsupported_token_type", "The access tokens cannot be revoked: they expire in a few minutes", http.StatusBadRequest)
		return
	}

	// invalid or unknown tokens also get a 200 response (RFC 7009 section 2.2)
	grant, err := h.grantStore.GetGrantByIDAndType(cryptography.SHA256(token), domain.GrantTypeRefresh)
	// the refresh tokens rotated from the same code are revoked too
	if err == nil && grant.Client().ClientID() == client.ClientID() {
		_ = h.grantStore.RevokeFamily(grant.FamilyID())
	}

	utils.NoCache(w)
	w.WriteHeader(http.StatusOK)
}

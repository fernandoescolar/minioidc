package handlers

import (
	"net/http"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// RevokeHandler implements RFC 7009 token revocation.
type RevokeHandler struct {
	now         func() time.Time
	keypair     *cryptography.Keypair
	clientStore domain.ClientStore
	grantStore  domain.GrantStore
	masterKey   string
}

var _ http.Handler = (*RevokeHandler)(nil)

func NewRevokeHandler(config *domain.Config, now func() time.Time) *RevokeHandler {
	return &RevokeHandler{
		now:         now,
		keypair:     config.Keypair,
		clientStore: config.ClientStore,
		grantStore:  config.GrantStore,
		masterKey:   config.MasterKey,
	}
}

func (h *RevokeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.Error(w, utils.InvalidRequest, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		if err := r.ParseForm(); err == nil {
			clientID = r.Form.Get("client_id")
			clientSecret = r.Form.Get("client_secret")
		}
	}

	if clientID == "" {
		utils.ErrorMissingParameter(w, "client_id")
		return
	}

	client, err := h.clientStore.GetClientByID(clientID)
	if err != nil || client == nil {
		utils.Error(w, utils.InvalidClient, "Invalid client", http.StatusUnauthorized)
		return
	}

	if !client.ClientSecretIsValid(clientSecret) {
		utils.Error(w, utils.InvalidClient, "Invalid client secret", http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		utils.Error(w, utils.InvalidRequest, "Invalid request", http.StatusBadRequest)
		return
	}

	token := r.Form.Get("token")
	if token == "" {
		utils.ErrorMissingParameter(w, "token")
		return
	}

	hint := r.Form.Get("token_type_hint")

	// Try refresh token first (or if hint says so).
	if hint == "" || hint == "refresh_token" {
		if h.revokeRefreshToken(token) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	// Try access token (JWT).
	if hint == "" || hint == "access_token" {
		h.revokeAccessToken(token)
	}

	// RFC 7009 §2.2: always 200 (we use 204) even if the token was not found.
	w.WriteHeader(http.StatusNoContent)
}

func (h *RevokeHandler) revokeRefreshToken(token string) bool {
	dr, err := cryptography.Decrypts(h.masterKey, token)
	if err != nil {
		return false
	}
	hr := cryptography.SHA256(dr)
	grant, err := h.grantStore.GetGrantByIDAndType(hr, domain.GrantTypeRefresh)
	if err != nil || grant == nil {
		return false
	}
	_ = h.grantStore.Grant(grant.ID())
	return true
}

func (h *RevokeHandler) revokeAccessToken(token string) {
	jwtToken, ok := utils.ValidateJWT(token, h.keypair, h.now())
	if !ok {
		return
	}
	grant, err := h.grantStore.GetGrantByToken(jwtToken)
	if err != nil || grant == nil {
		return
	}
	_ = h.grantStore.Grant(grant.ID())
}

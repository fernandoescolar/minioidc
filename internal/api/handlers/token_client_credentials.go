package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// requestWithClientCredentials implements the client credentials grant (RFC
// 6749 section 4.4): an access token of the client itself, without user. It
// has no refresh token (section 4.4.3) and no ID token (there is no user).
func (h *TokenHandler) requestWithClientCredentials(w http.ResponseWriter, r *http.Request, client domain.Client) {
	if client.IsPublic() {
		utils.Error(w, utils.UnauthorizedClient, "Public clients cannot use client_credentials", http.StatusBadRequest)
		return
	}

	// the scopes of this server are about users: a client token has none
	if scope := strings.TrimSpace(r.PostForm.Get("scope")); scope != "" {
		utils.Error(w, utils.InvalidScope, "The client_credentials tokens have no user scopes", http.StatusBadRequest)
		return
	}

	accessToken, err := domain.ClientAccessToken(h.issuer, h.audience, client.ClientID(), nil, h.accessTTL, h.keypair, h.now())
	if err != nil {
		utils.InternalServerError(w, fmt.Sprintf("creating access token: %v", err))
		return
	}

	resp, err := json.Marshal(&tokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(h.accessTTL.Seconds()),
	})
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	utils.JSON(w, resp)
}

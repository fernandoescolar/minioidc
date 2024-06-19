package handlers

import (
	"log"
	"net/http"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

func (h *TokenHandler) refreshTokenGrant(tokenReq *tokenRequest, w http.ResponseWriter) domain.Grant {
	if tokenReq.RefreshToken == "" {
		utils.ErrorMissingParameter(w, "refresh_token")
		return nil
	}

	if tokenReq.ClientID == "" {
		utils.ErrorMissingParameter(w, "client_id")
		return nil
	}

	if tokenReq.ClientSecret == "" {
		utils.ErrorMissingParameter(w, "client_secret")
		return nil
	}

	_, err := h.clientStore.GetClientByID(tokenReq.ClientID)
	if err != nil {
		utils.Error(w, utils.InvalidClient, "Invalid client id", http.StatusUnauthorized)
		return nil
	}

	// validSecret := client.ClientSecretIsValid(tokenReq.ClientSecret)
	// if !validSecret {
	// 	errorResponse(rw, InvalidClient, "Invalid client secret", http.StatusUnauthorized)
	// 	return nil, false
	// }

	dr, err := cryptography.Decrypts(h.masterKey, tokenReq.RefreshToken)
	if err != nil {
		log.Println("Error: getting refresh token: %w", err)
		utils.InternalServerError(w, err.Error())
		return nil
	}

	hr := cryptography.SHA256(dr)
	grant, err := h.grantStore.GetGrantByIDAndType(hr, domain.GrantTypeRefresh)
	if err != nil {
		utils.Error(w, utils.InvalidGrant, "Invalid refresh token",
			http.StatusUnauthorized)
		return nil
	}

	if !h.reUseRefreshTokens {
		h.grantStore.Grant(grant.ID())
	}

	return grant
}

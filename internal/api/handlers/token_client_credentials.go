package handlers

import (
	"net/http"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/internal/stores"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

func (h *TokenHandler) clientCredentialsGrant(tokenReq *tokenRequest, w http.ResponseWriter) domain.Grant {
	if tokenReq.ClientID == "" {
		utils.ErrorMissingParameter(w, "client_id")
		return nil
	}

	if tokenReq.ClientSecret == "" {
		utils.ErrorMissingParameter(w, "client_secret")
		return nil
	}

	client, err := h.clientStore.GetClientByID(tokenReq.ClientID)
	if err != nil {
		utils.Error(w, utils.InvalidClient, "Invalid client id", http.StatusUnauthorized)
		return nil
	}

	if !client.ClientSecretIsValid(tokenReq.ClientSecret) {
		utils.Error(w, utils.InvalidClient, "Invalid client secret", http.StatusUnauthorized)
		return nil
	}

	if !client.ScopesAreValid(tokenReq.Scopes) {
		utils.Error(w, utils.InvalidScope, "Invalid scope", http.StatusUnauthorized)
		return nil
	}

	id := stores.CreateComplexUID()
	user := domain.NewUser(tokenReq.ClientID, "", "", "", "", []string{}, "")
	session := domain.NewSession(id, user, false, h.now().Add(h.accessTTL))

	return domain.NewGrant(
		id,
		domain.GrantTypeCode,
		client,
		session,
		h.now().Add(h.accessTTL),
		tokenReq.Scopes,
		"",
		"",
		"")
}

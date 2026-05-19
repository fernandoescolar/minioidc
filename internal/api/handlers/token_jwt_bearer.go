package handlers

import (
	"net/http"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/internal/stores"
	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/golang-jwt/jwt"
)

func (h *TokenHandler) jwtBearerGrant(tokenReq *tokenRequest, w http.ResponseWriter) domain.Grant {
	if tokenReq.ClientID == "" {
		utils.ErrorMissingParameter(w, "client_id")
		return nil
	}

	if tokenReq.Assertion == "" {
		utils.ErrorMissingParameter(w, "assertion")
		return nil
	}

	client, err := h.clientStore.GetClientByID(tokenReq.ClientID)
	if err != nil {
		utils.Error(w, utils.InvalidClient, "Invalid client id", http.StatusUnauthorized)
		return nil
	}

	token, ok := utils.ValidateJWT(tokenReq.Assertion, h.keypair, h.now())
	if !ok {
		utils.Error(w, utils.InvalidRequest, "Invalid assertion", http.StatusUnauthorized)
		return nil
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		utils.Error(w, utils.InvalidRequest, "Invalid assertion claims", http.StatusUnauthorized)
		return nil
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		utils.Error(w, utils.InvalidRequest, "Missing sub in assertion", http.StatusUnauthorized)
		return nil
	}

	user, err := h.userStore.GetUserByID(sub)
	if err != nil {
		utils.Error(w, utils.InvalidRequest, "User not found", http.StatusUnauthorized)
		return nil
	}

	scopes := tokenReq.Scopes
	if len(scopes) > 0 && !client.ScopesAreValid(scopes) {
		utils.Error(w, utils.InvalidScope, "Invalid scope", http.StatusBadRequest)
		return nil
	}

	sessionID := stores.CreateComplexUID()
	session, err := h.sessionStore.NewSession(sessionID, user, h.now().Add(h.accessTTL), false)
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return nil
	}

	grantID := stores.CreateComplexUID()
	grant, err := h.grantStore.NewCodeGrant(grantID, client, session, h.now(), h.now().Add(h.accessTTL), scopes, "", "", "")
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return nil
	}

	return grant
}

package handlers

import (
	"fmt"
	"log"
	"net/http"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

func (h *TokenHandler) authorizationCodeGrant(tokenReq *tokenRequest, w http.ResponseWriter) domain.Grant {
	if tokenReq.Code == "" {
		utils.ErrorMissingParameter(w, "code")
		return nil
	}

	if tokenReq.RedirectURI == "" {
		utils.ErrorMissingParameter(w, "redirect_uri")
		return nil
	}

	code, err := cryptography.Decrypts(h.masterKey, tokenReq.Code)
	if err != nil {
		log.Println("Error: getting code: %w", err)
		utils.InternalServerError(w, err.Error())
		return nil
	}

	code = cryptography.SHA256(code)
	grant, err := h.grantStore.GetGrantByIDAndType(code, domain.GrantTypeCode)
	if err != nil || grant.HasBeenGranted() {
		utils.Error(w, utils.InvalidGrant, fmt.Sprintf("Invalid code: %s", code), http.StatusUnauthorized)
		return nil
	}

	if !grant.Client().RedirectURLIsValid(tokenReq.RedirectURI) {
		utils.Error(w, utils.InvalidRequest, "Invalid redirect uri", http.StatusBadRequest)
		return nil
	}

	if !h.validateCodeChallenge(grant, tokenReq, w) {
		return nil
	}

	if err := h.grantStore.Grant(grant.ID()); err != nil {
		log.Println("Error granting code:", err)
	}

	return grant
}

func (h *TokenHandler) validateCodeChallenge(grant domain.Grant, tokenReq *tokenRequest, w http.ResponseWriter) bool {
	if grant.CodeChallenge() == "" || grant.CodeChallengeMethod() == "" {
		return true
	}

	if tokenReq.CodeVerifier == "" {
		utils.ErrorMissingParameter(w, "code_verifier")
		return false
	}

	challenge, err := cryptography.GenerateCodeChallenge(grant.CodeChallengeMethod(), tokenReq.CodeVerifier)
	if err != nil {
		utils.Error(w, utils.InvalidRequest, fmt.Sprintf("Invalid code verifier. %v", err.Error()), http.StatusUnauthorized)
		return false
	}

	if challenge != grant.CodeChallenge() {
		utils.Error(w, utils.InvalidGrant, "Invalid code verifier. Code challenge did not match hashed code verifier.", http.StatusUnauthorized)
		return false
	}

	return true
}

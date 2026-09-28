package handlers

import (
	"errors"
	"net/http"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/internal/clientauth"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// ClientAuthenticator authenticates the client of a request with a parsed form
type ClientAuthenticator interface {
	Authenticate(r *http.Request, endpointURL string) (domain.Client, error)
}

// authenticateClient authenticates the client and writes the error response if it fails
func authenticateClient(authenticator ClientAuthenticator, endpointURL string, w http.ResponseWriter, r *http.Request) (domain.Client, bool) {
	client, err := authenticator.Authenticate(r, endpointURL)
	if err == nil {
		return client, true
	}

	var authErr *clientauth.Error
	if !errors.As(err, &authErr) {
		utils.InternalServerError(w, err.Error())
		return nil, false
	}

	if authErr.Code == utils.InvalidRequest {
		utils.Error(w, authErr.Code, authErr.Description, http.StatusBadRequest)
		return nil, false
	}

	if authErr.Basic {
		w.Header().Set("WWW-Authenticate", `Basic realm="minioidc"`)
	}

	// the details are logged, but not sent to the client
	if authErr.Description != "Client authentication failed" {
		utils.LogDebug("client authentication: %s", authErr.Description)
	}

	utils.Error(w, utils.InvalidClient, "Client authentication failed", http.StatusUnauthorized)
	return nil, false
}

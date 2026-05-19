package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/go-jose/go-jose/v4"
)

type JWKSHandler struct {
	keypair *cryptography.Keypair
}

var _ http.Handler = (*JWKSHandler)(nil)

func NewJWKSHandler(config *domain.Config) *JWKSHandler {
	return &JWKSHandler{
		keypair: config.Keypair,
	}
}

func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	jwks, err := h.jwks()
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	utils.NoCache(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(jwks)
}

func (h *JWKSHandler) jwks() ([]byte, error) {
	kid, err := h.keypair.KeyID()
	if err != nil {
		return nil, err
	}

	jwk := jose.JSONWebKey{
		Use:       "sig",
		Algorithm: string(jose.RS256),
		Key:       h.keypair.PublicKey,
		KeyID:     kid,
	}
	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	return json.Marshal(jwks)
}

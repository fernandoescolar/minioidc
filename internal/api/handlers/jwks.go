package handlers

import (
	"net/http"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
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
	jwks, err := h.keypair.JWKS()
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	utils.JSON(w, jwks)
}

package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/api/handlers/responses"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/golang-jwt/jwt"
)

type UserinfoHandler struct {
	now        func() time.Time
	keypair    *cryptography.Keypair
	grantStore domain.GrantStore
}

func NewUserinfoHandler(config *domain.Config, now func() time.Time) *UserinfoHandler {
	return &UserinfoHandler{
		now:        now,
		keypair:    config.Keypair,
		grantStore: config.GrantStore,
	}
}

func (h *UserinfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token, authorized := h.authorizeBearer(w, r)
	if !authorized {
		return
	}

	grant, err := h.grantStore.GetGrantByToken(token)
	if err != nil {
		responses.InternalServerError(w, err.Error())
		return
	}

	resp, err := grant.User().Userinfo(grant.Scopes())
	if err != nil {
		responses.InternalServerError(w, err.Error())
		return
	}

	responses.JSON(w, resp)
}

func (h *UserinfoHandler) authorizeBearer(w http.ResponseWriter, r *http.Request) (*jwt.Token, bool) {
	header := r.Header.Get("Authorization")
	parts := strings.SplitN(header, " ", 2)
	if len(parts) < 2 || parts[0] != "Bearer" {
		responses.Error(w, responses.InvalidRequest, "Invalid authorization header", http.StatusUnauthorized)
		return nil, false
	}

	return h.authorizeToken(parts[1], w)
}

func (h *UserinfoHandler) authorizeToken(t string, w http.ResponseWriter) (*jwt.Token, bool) {
	token, err := h.keypair.VerifyJWT(t)
	if err != nil {
		responses.Error(w, responses.InvalidRequest, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
		return nil, false
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		responses.InternalServerError(w, "Unable to extract token claims")
		return nil, false
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		responses.InternalServerError(w, "Unable to extract token expiration")
		return nil, false
	}

	if h.now().Unix() > int64(exp) {
		responses.Error(w, responses.InvalidRequest, "The token is expired", http.StatusUnauthorized)
		return nil, false
	}

	return token, true
}

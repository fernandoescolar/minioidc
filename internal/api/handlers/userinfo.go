package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

const AuthorizationParts = 2

type UserinfoHandler struct {
	validator *accessTokenValidator
}

var _ http.Handler = (*UserinfoHandler)(nil)

func NewUserinfoHandler(config *domain.Config, now func() time.Time) *UserinfoHandler {
	return &UserinfoHandler{
		validator: newAccessTokenValidator(config, now),
	}
}

func (h *UserinfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		utils.Error(w, utils.InvalidRequest, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	accessToken, ok := bearerToken(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="minioidc"`)
		utils.Error(w, utils.InvalidRequest, "Missing or invalid access token", http.StatusUnauthorized)
		return
	}

	claims, session, err := h.validator.validate(accessToken)
	// the client tokens (client_credentials) have no user
	if err != nil || session == nil {
		invalidToken(w, "Invalid token")
		return
	}

	resp, err := session.User().Userinfo(strings.Split(claims.Scope, " "))
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	utils.JSON(w, resp)
}

// bearerToken reads the access token from the Authorization header or from
// the form body of a POST request (RFC 6750 sections 2.1 and 2.2)
func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	body := ""
	if r.Method == http.MethodPost && r.ParseForm() == nil {
		body = r.PostForm.Get("access_token")
	}

	switch {
	case header != "" && body != "":
		// RFC 6750: only one method can be used
		return "", false
	case header != "":
		parts := strings.SplitN(header, " ", AuthorizationParts)
		if len(parts) < AuthorizationParts || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
			return "", false
		}

		return parts[1], true
	default:
		return body, body != ""
	}
}

func invalidToken(w http.ResponseWriter, description string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="minioidc", error="invalid_token"`)
	utils.Error(w, utils.InvalidToken, description, http.StatusUnauthorized)
}

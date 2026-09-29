package handlers

import (
	"net/http"
	"strings"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// requestWithJWTBearer implements the JWT bearer authorization grant (RFC 7523
// section 2.1): the client asserts, with a JWT signed with its own registered
// keys, the user it acts for (the sub claim). The client can get tokens of any
// user, so the grant must be enabled explicitly in the client. No ID token is
// issued: the user has not authenticated.
func (h *TokenHandler) requestWithJWTBearer(w http.ResponseWriter, r *http.Request, client domain.Client) {
	if client.IsPublic() {
		utils.Error(w, utils.UnauthorizedClient, "Public clients cannot use the jwt-bearer grant", http.StatusBadRequest)
		return
	}

	if !assertPresenceInForm([]string{"assertion"}, w, r) {
		return
	}

	scopes := strings.Fields(r.PostForm.Get("scope"))
	if errCode, description := validateScope(strings.Join(scopes, " ")); len(scopes) > 0 && errCode != "" {
		utils.Error(w, errCode, description, http.StatusBadRequest)
		return
	}

	claims, err := h.authenticator.VerifyGrantAssertion(client, r.PostForm.Get("assertion"), h.endpointURL)
	if err != nil {
		utils.LogDebug("jwt-bearer grant: %v", err)
		utils.Error(w, utils.InvalidGrant, "Invalid assertion", http.StatusBadRequest)
		return
	}

	user, err := h.userStore.GetUserByID(claims.Subject)
	if err != nil {
		utils.Error(w, utils.InvalidGrant, "Invalid assertion", http.StatusBadRequest)
		return
	}

	h.issueForUser(w, client, user, scopes, h.now(), false, false)
}

package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/internal/stores"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// requestWithDeviceCode implements the device access token request (RFC 8628
// section 3.4). The code can only be exchanged by the client it was issued to,
// and only once: the store consumes it atomically.
func (h *TokenHandler) requestWithDeviceCode(w http.ResponseWriter, r *http.Request, client domain.Client) {
	if !assertPresenceInForm([]string{"device_code"}, w, r) {
		return
	}

	now := h.now()
	code, result, err := h.deviceCodeStore.Poll(cryptography.SHA256(r.PostForm.Get("device_code")), client.ClientID(), now)
	if err != nil {
		utils.Error(w, utils.InvalidGrant, "Invalid device code", http.StatusBadRequest)
		return
	}

	switch result {
	case domain.DevicePending:
		utils.Error(w, "authorization_pending", "The user has not authorized the device yet", http.StatusBadRequest)
	case domain.DeviceSlowDown:
		utils.Error(w, "slow_down", fmt.Sprintf("Poll every %d seconds", code.Interval), http.StatusBadRequest)
	case domain.DeviceDenied:
		utils.Error(w, "access_denied", "The user denied the authorization", http.StatusBadRequest)
	case domain.DeviceExpired:
		utils.Error(w, "expired_token", "The device code has expired", http.StatusBadRequest)
	case domain.DeviceApproved:
		user, err := h.userStore.GetUserByID(code.UserID)
		if err != nil {
			utils.Error(w, utils.InvalidGrant, "The user does not exist", http.StatusBadRequest)
			return
		}

		h.issueForUserAt(w, client, user, code.Scopes, now, code.AuthTime, code.MFAVerified, true)
	}
}

// issueForUser creates a session for the user and issues the tokens of the
// scopes: the refresh token with offline_access and, when idToken is true,
// the ID token with openid
func (h *TokenHandler) issueForUser(w http.ResponseWriter, client domain.Client, user domain.User, scopes []string, now time.Time, mfaVerified, idToken bool) {
	h.issueForUserAt(w, client, user, scopes, now, now, mfaVerified, idToken)
}

func (h *TokenHandler) issueForUserAt(w http.ResponseWriter, client domain.Client, user domain.User, scopes []string, now, authTime time.Time, mfaVerified, idToken bool) {
	session, err := h.sessionStore.NewSession(stores.CreateUID(), user, authTime, now.Add(h.sessionTTL), false)
	if err != nil {
		utils.InternalServerError(w, fmt.Sprintf("creating session: %v", err))
		return
	}

	if mfaVerified {
		if err := h.sessionStore.VerifyMFA(session.ID()); err != nil {
			utils.InternalServerError(w, fmt.Sprintf("verifying mfa: %v", err))
			return
		}

		if session, err = h.sessionStore.GetSessionByID(session.ID()); err != nil {
			utils.InternalServerError(w, err.Error())
			return
		}
	}

	grantID, err := cryptography.RandomToken()
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	// a grant that is not stored: it describes the tokens and it is the family
	// of the refresh tokens
	grant := domain.NewGrant(domain.GrantData{
		ID:        cryptography.SHA256(grantID),
		FamilyID:  cryptography.SHA256(grantID),
		GrantType: domain.GrantTypeCode,
		ExpiresAt: now.Add(h.accessTTL),
		Scopes:    nonEmpty(scopes),
	}, client, session)

	refreshToken := ""
	if grant.HasScope(offlineAccessScope) && client.GrantTypeAllowed(domain.GrantTypeRefreshToken) {
		if refreshToken, err = h.createRefreshToken(grant); err != nil {
			utils.InternalServerError(w, err.Error())
			return
		}
	}

	h.writeTokens(w, grant, refreshToken, idToken)
}

func nonEmpty(scopes []string) []string {
	result := []string{}
	for _, s := range scopes {
		if s = strings.TrimSpace(s); s != "" {
			result = append(result, s)
		}
	}

	return result
}

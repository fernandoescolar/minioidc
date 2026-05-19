package handlers

import (
	"net/http"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/internal/stores"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

func (h *TokenHandler) deviceCodeGrant(tokenReq *tokenRequest, w http.ResponseWriter) domain.Grant {
	if tokenReq.ClientID == "" {
		utils.ErrorMissingParameter(w, "client_id")
		return nil
	}

	if tokenReq.DeviceCode == "" {
		utils.ErrorMissingParameter(w, "device_code")
		return nil
	}

	dc, err := h.deviceCodeStore.GetDeviceCodeByCode(tokenReq.DeviceCode)
	if err != nil {
		utils.Error(w, "expired_token", "Device code not found or expired", http.StatusBadRequest)
		return nil
	}

	if dc.HasExpired() {
		_ = h.deviceCodeStore.Delete(dc.DeviceCode)
		utils.Error(w, "expired_token", "Device code has expired", http.StatusBadRequest)
		return nil
	}

	if dc.Denied {
		_ = h.deviceCodeStore.Delete(dc.DeviceCode)
		utils.Error(w, "access_denied", "User denied access", http.StatusBadRequest)
		return nil
	}

	if !dc.Approved {
		// Enforce slow_down if polled faster than the interval.
		now := h.now()
		if !dc.LastPolled.IsZero() && now.Sub(dc.LastPolled) < time.Duration(dc.Interval)*time.Second {
			utils.Error(w, "slow_down", "Polling too fast", http.StatusBadRequest)
			return nil
		}
		_ = h.deviceCodeStore.UpdatePolled(dc.DeviceCode, now)
		utils.Error(w, "authorization_pending", "Authorization pending", http.StatusBadRequest)
		return nil
	}

	user, err := h.userStore.GetUserByID(dc.UserID)
	if err != nil {
		utils.Error(w, utils.InvalidRequest, "User not found", http.StatusUnauthorized)
		return nil
	}

	client, err := h.clientStore.GetClientByID(dc.ClientID)
	if err != nil {
		utils.Error(w, utils.InvalidClient, "Invalid client id", http.StatusUnauthorized)
		return nil
	}

	scopes := dc.Scopes

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

	_ = h.deviceCodeStore.Delete(dc.DeviceCode)
	return grant
}

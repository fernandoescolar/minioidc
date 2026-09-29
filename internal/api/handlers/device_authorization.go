package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/internal/stores"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

const (
	// DeviceCodeTTL is the lifetime of the device and user codes
	DeviceCodeTTL = 10 * time.Minute
	// DevicePollInterval is the minimum seconds between the polls of a device
	DevicePollInterval = 5
	userCodeAttempts   = 5
)

// DeviceAuthorizationHandler implements the device authorization endpoint (RFC 8628 section 3.1)
type DeviceAuthorizationHandler struct {
	now             func() time.Time
	deviceCodeStore domain.DeviceCodeStore
	authenticator   ClientAuthenticator
	endpointURL     string
	verificationURI string
}

type deviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

var _ http.Handler = (*DeviceAuthorizationHandler)(nil)

func NewDeviceAuthorizationHandler(config *domain.Config, now func() time.Time, authenticator ClientAuthenticator, endpointURL, verificationURI string) *DeviceAuthorizationHandler {
	return &DeviceAuthorizationHandler{
		now:             now,
		deviceCodeStore: config.DeviceCodeStore,
		authenticator:   authenticator,
		endpointURL:     endpointURL,
		verificationURI: verificationURI,
	}
}

func (h *DeviceAuthorizationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.Error(w, utils.InvalidRequest, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		utils.Error(w, utils.InvalidRequest, "Invalid form", http.StatusBadRequest)
		return
	}

	// public clients (e.g. TVs or CLIs) authenticate with their client_id
	client, ok := authenticateClient(h.authenticator, h.endpointURL, w, r)
	if !ok {
		return
	}

	if !client.GrantTypeAllowed(domain.GrantTypeDeviceCode) {
		utils.Error(w, utils.UnauthorizedClient, "The client is not allowed to use the device flow", http.StatusBadRequest)
		return
	}

	scopes := strings.Fields(r.PostForm.Get("scope"))
	if errCode, description := validateScope(strings.Join(scopes, " ")); len(scopes) > 0 && errCode != "" {
		utils.Error(w, errCode, description, http.StatusBadRequest)
		return
	}

	deviceCode, err := cryptography.RandomToken()
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	userCode, err := h.newCode(deviceCode, client.ClientID(), scopes)
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	formatted := stores.FormatUserCode(userCode)
	resp, err := json.Marshal(&deviceAuthorizationResponse{
		DeviceCode:              deviceCode,
		UserCode:                formatted,
		VerificationURI:         h.verificationURI,
		VerificationURIComplete: h.verificationURI + "?user_code=" + url.QueryEscape(formatted),
		ExpiresIn:               int(DeviceCodeTTL.Seconds()),
		Interval:                DevicePollInterval,
	})
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	utils.JSON(w, resp)
}

// newCode stores the device code with a new user code, retrying when the
// random user code already exists
func (h *DeviceAuthorizationHandler) newCode(deviceCode, clientID string, scopes []string) (string, error) {
	for attempt := 0; attempt < userCodeAttempts; attempt++ {
		userCode, err := stores.GenerateUserCode()
		if err != nil {
			return "", err
		}

		err = h.deviceCodeStore.NewDeviceCode(domain.DeviceCode{
			DeviceCodeHash: cryptography.SHA256(deviceCode),
			UserCode:       userCode,
			ClientID:       clientID,
			Scopes:         scopes,
			ExpiresAt:      h.now().Add(DeviceCodeTTL),
			Interval:       DevicePollInterval,
		})
		if err == nil {
			return userCode, nil
		}
	}

	return "", fmt.Errorf("creating a unique user code")
}

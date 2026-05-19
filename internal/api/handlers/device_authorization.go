package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/internal/stores"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type DeviceAuthorizationHandler struct {
	now             func() time.Time
	issuer          string
	codeTTL         time.Duration
	clientStore     domain.ClientStore
	deviceCodeStore domain.DeviceCodeStore
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

func NewDeviceAuthorizationHandler(config *domain.Config, now func() time.Time) *DeviceAuthorizationHandler {
	return &DeviceAuthorizationHandler{
		now:             now,
		issuer:          config.Issuer,
		codeTTL:         config.CodeTTL,
		clientStore:     config.ClientStore,
		deviceCodeStore: config.DeviceCodeStore,
	}
}

func (h *DeviceAuthorizationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.Error(w, utils.InvalidRequest, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}

	if clientID == "" {
		utils.ErrorMissingParameter(w, "client_id")
		return
	}

	client, err := h.clientStore.GetClientByID(clientID)
	if err != nil {
		utils.Error(w, utils.InvalidClient, "Invalid client id", http.StatusUnauthorized)
		return
	}

	// Confidential clients must provide valid secret; public clients skip secret check.
	if !client.RequirePKCE() && !client.ClientSecretIsValid(clientSecret) {
		utils.Error(w, utils.InvalidClient, "Invalid client secret", http.StatusUnauthorized)
		return
	}

	scopes := utils.ParseSpaceSeparatedString(r.Form.Get("scope"))
	if len(scopes) > 0 && !client.ScopesAreValid(scopes) {
		utils.Error(w, utils.InvalidScope, "Invalid scope", http.StatusBadRequest)
		return
	}

	deviceCode := stores.CreateComplexUID()
	userCode, err := stores.GenerateUserCode()
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	now := h.now()
	expiresAt := now.Add(h.codeTTL)
	_, err = h.deviceCodeStore.NewDeviceCode(deviceCode, userCode, clientID, scopes, now, expiresAt, 5)
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	issuer := utils.GetIssuer(h.issuer, r)
	verificationURI := issuerWithoutTrailingSlash(issuer) + DeviceEndpoint
	resp := &deviceAuthorizationResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: verificationURI + "?user_code=" + userCode,
		ExpiresIn:               int(h.codeTTL.Seconds()),
		Interval:                5,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// DeviceEndpoint is the path for the user-facing device activation page.
// It is set by the router and referenced here to build verification URIs.
const DeviceEndpoint = "/connect/device"

package handlers

import (
	"html/template"
	"log"
	"net/http"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type DeviceHandler struct {
	name            string
	templates       []string
	deviceCodeStore domain.DeviceCodeStore
}

type deviceModel struct {
	Name       string
	CSRF       string
	UserCode   string
	ClientID   string
	Scopes     []string
	Error      string
	Authorized bool
	Denied     bool
}

var _ http.Handler = (*DeviceHandler)(nil)

func NewDeviceHandler(config *domain.Config) *DeviceHandler {
	return &DeviceHandler{
		name:            config.Name,
		templates:       []string{config.BaseTemplateFilepath, config.DeviceTemplateFilepath},
		deviceCodeStore: config.DeviceCodeStore,
	}
}

func (h *DeviceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		h.getHTTP(w, r)
		return
	}
	if r.Method == http.MethodPost {
		h.postHTTP(w, r)
		return
	}
	http.NotFound(w, r)
}

func (h *DeviceHandler) getHTTP(w http.ResponseWriter, r *http.Request) {
	csrf := utils.GetCSRFToken(r)
	userCode := r.URL.Query().Get("user_code")
	model := &deviceModel{
		Name:     h.name,
		CSRF:     csrf,
		UserCode: userCode,
	}

	if userCode != "" {
		dc, err := h.deviceCodeStore.GetDeviceCodeByUserCode(userCode)
		if err == nil && !dc.HasExpired() {
			model.ClientID = dc.ClientID
			model.Scopes = dc.Scopes
		}
	}

	h.render(w, model)
}

func (h *DeviceHandler) postHTTP(w http.ResponseWriter, r *http.Request) {
	if !utils.GetCSRFValid(r) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	csrf := utils.GetCSRFToken(r)
	userCode := r.FormValue("user_code")
	action := r.FormValue("action")

	model := &deviceModel{
		Name:     h.name,
		CSRF:     csrf,
		UserCode: userCode,
	}

	if userCode == "" {
		model.Error = "User code is required"
		h.render(w, model)
		return
	}

	dc, err := h.deviceCodeStore.GetDeviceCodeByUserCode(userCode)
	if err != nil {
		model.Error = "Invalid or unknown user code"
		h.render(w, model)
		return
	}

	if dc.HasExpired() {
		model.Error = "This code has expired. Please start the device flow again."
		h.render(w, model)
		return
	}

	model.ClientID = dc.ClientID
	model.Scopes = dc.Scopes

	session := utils.GetSession(r)

	switch action {
	case "approve":
		if err := h.deviceCodeStore.Approve(dc.DeviceCode, session.User().ID()); err != nil {
			model.Error = "Failed to approve device"
			h.render(w, model)
			return
		}
		model.Authorized = true
	case "deny":
		if err := h.deviceCodeStore.Deny(dc.DeviceCode); err != nil {
			model.Error = "Failed to deny device"
			h.render(w, model)
			return
		}
		model.Denied = true
	default:
		model.Error = "Unknown action"
	}

	h.render(w, model)
}

func (h *DeviceHandler) render(w http.ResponseWriter, model *deviceModel) {
	tmpl, err := template.ParseFiles(h.templates...)
	if err != nil {
		log.Printf("DeviceHandler: template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := tmpl.Execute(w, model); err != nil {
		log.Printf("DeviceHandler: execute error: %v", err)
	}
}

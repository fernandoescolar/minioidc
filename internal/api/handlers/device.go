package handlers

import (
	"html/template"
	"net/http"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/internal/stores"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// DeviceHandler is the page where the users authorize a device (RFC 8628
// section 3.3). The session middlewares require a session with the MFA verified.
type DeviceHandler struct {
	name            string
	now             func() time.Time
	template        *template.Template
	deviceCodeStore domain.DeviceCodeStore
	userBlocked     domain.UserBlockedStore
}

type deviceModel struct {
	Name            string
	CSRF            string
	UserCode        string
	ClientID        string
	Scopes          []string
	Error           string
	TooManyAttempts bool
	Authorized      bool
	Denied          bool
	FormExpired     bool
}

var _ http.Handler = (*DeviceHandler)(nil)

func NewDeviceHandler(config *domain.Config, now func() time.Time) *DeviceHandler {
	return &DeviceHandler{
		name:            config.Name,
		now:             now,
		template:        utils.ParseTemplates(config.BasePath, config.BaseTemplateFilepath, config.DeviceTemplateFilepath),
		deviceCodeStore: config.DeviceCodeStore,
		userBlocked:     config.UserBlockedStore,
	}
}

func (h *DeviceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session := utils.GetSession(r)
	if session == nil {
		utils.InternalServerError(w, "Failed to get session")
		return
	}

	switch r.Method {
	case http.MethodGet:
		model := &deviceModel{CSRF: utils.GetCSRFToken(r), UserCode: r.URL.Query().Get("user_code")}
		if model.UserCode != "" {
			h.lookup(session, model)
		}
		h.render(w, model)
	case http.MethodPost:
		h.postHTTP(w, r, session)
	default:
		http.NotFound(w, r)
	}
}

func (h *DeviceHandler) postHTTP(w http.ResponseWriter, r *http.Request, session domain.Session) {
	if !utils.GetCSRFValid(r) {
		h.render(w, &deviceModel{CSRF: utils.GetCSRFToken(r), FormExpired: true})
		return
	}

	model := &deviceModel{CSRF: utils.GetCSRFToken(r), UserCode: r.PostFormValue("user_code")}
	if !h.lookup(session, model) {
		h.render(w, model)
		return
	}

	now := h.now()
	switch r.PostFormValue("action") {
	case "approve":
		mfa := contains("mfa", session.AuthMethods())
		if err := h.deviceCodeStore.Approve(model.UserCode, session.User().ID(), session.AuthTime(), mfa, now); err != nil {
			model.Error = "This code is no longer valid"
			break
		}
		model.Authorized = true
	case "deny":
		if err := h.deviceCodeStore.Deny(model.UserCode, now); err != nil {
			model.Error = "This code is no longer valid"
			break
		}
		model.Denied = true
	}

	h.render(w, model)
}

// lookup fills the client of a pending user code. The failed lookups count as
// failed attempts, so the user codes cannot be guessed (RFC 8628 section 5.1).
func (h *DeviceHandler) lookup(session domain.Session, model *deviceModel) bool {
	now := h.now()
	blockKey := "device:" + session.User().ID()
	if h.userBlocked.IsBlocked(blockKey, now) {
		model.TooManyAttempts = true
		return false
	}

	code, err := h.deviceCodeStore.GetDeviceCodeByUserCode(model.UserCode, now)
	if err != nil {
		model.TooManyAttempts = h.userBlocked.AddFailedAttempt(blockKey, now)
		if !model.TooManyAttempts {
			model.Error = "Invalid or expired code"
		}
		return false
	}

	h.userBlocked.Reset(blockKey)
	model.UserCode = stores.FormatUserCode(code.UserCode)
	model.ClientID = code.ClientID
	model.Scopes = code.Scopes
	return true
}

func (h *DeviceHandler) render(w http.ResponseWriter, model *deviceModel) {
	model.Name = h.name
	utils.RenderTemplate(w, h.template, model)
}

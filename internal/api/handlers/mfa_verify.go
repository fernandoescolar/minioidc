package handlers

import (
	"html/template"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type MFAVerifyHandler struct {
	now            func() time.Time
	template       *template.Template
	issuer         string
	createEndpoint string
	mfaStore       domain.MFACodeStore
	sessionStore   domain.SessionStore
	userBlocked    domain.UserBlockedStore
	events         *domain.Recorder
	home           string
}

type mfaVerifyModel struct {
	Name                    string
	InvalidVerificationCode bool
	TooManyAttempts         bool
	UnknownError            bool
	FormExpired             bool
	CSRF                    string
}

var _ http.Handler = (*MFAVerifyHandler)(nil)

func NewMfaVerifyHandler(config *domain.Config, now func() time.Time, createEndpoint string) *MFAVerifyHandler {
	return &MFAVerifyHandler{
		now:            now,
		template:       utils.ParseTemplates(config.BasePath, config.BaseTemplateFilepath, config.MFAVerifyTemplateFilepath),
		issuer:         config.Name,
		createEndpoint: createEndpoint,
		mfaStore:       config.MFACodeStore,
		sessionStore:   config.SessionStore,
		userBlocked:    config.UserBlockedStore,
		events:         config.Events,
		home:           config.BasePath + "/",
	}
}

func (h *MFAVerifyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getHTTP(w, r)
	case http.MethodPost:
		h.postHTTP(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *MFAVerifyHandler) getHTTP(w http.ResponseWriter, r *http.Request) {
	session := utils.GetSession(r)
	if session == nil {
		utils.InternalServerError(w, "Failed to get session")
		return
	}

	hasMFA, err := h.mfaStore.UserHasMFACodes(session.User().ID())
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	if !hasMFA {
		location := h.createEndpoint + "?return_url=" + url.QueryEscape(utils.GetReturnURL(r, h.home))
		http.Redirect(w, r, location, http.StatusFound)
		return
	}

	h.render(w, r, mfaVerifyModel{})
}

func (h *MFAVerifyHandler) postHTTP(w http.ResponseWriter, r *http.Request) {
	if !utils.GetCSRFValid(r) {
		h.render(w, r, mfaVerifyModel{FormExpired: true})
		return
	}

	session := utils.GetSession(r)
	if session == nil {
		utils.InternalServerError(w, "Failed to get session")
		return
	}

	verificationCode := r.PostFormValue("verification_code")
	if verificationCode == "" {
		utils.Error(w, utils.InvalidRequest, "Missing verification_code", http.StatusBadRequest)
		return
	}

	mfas, err := h.mfaStore.GetMFACodeByUserID(session.User().ID())
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	if len(mfas) == 0 {
		location := h.createEndpoint + "?return_url=" + url.QueryEscape(utils.GetReturnURL(r, h.home))
		http.Redirect(w, r, location, http.StatusFound)
		return
	}

	now := h.now()
	blockKey := "mfa:" + session.User().ID()
	user := session.User()
	if h.userBlocked.IsBlocked(blockKey, now) {
		h.events.RecordUser(r, domain.EventLoginMFA, domain.ResultFailure, user, "blocked: too many failed attempts")
		h.render(w, r, mfaVerifyModel{TooManyAttempts: true})
		return
	}

	if !verifyAnyMFA(mfas, verificationCode, now) {
		blocked := h.userBlocked.AddFailedAttempt(blockKey, now)
		h.events.RecordUser(r, domain.EventLoginMFA, domain.ResultFailure, user, "invalid code")
		if blocked {
			h.events.RecordUser(r, domain.EventLoginLockout, domain.ResultFailure, user, "the MFA codes")
		}
		h.render(w, r, mfaVerifyModel{InvalidVerificationCode: !blocked, TooManyAttempts: blocked})
		return
	}

	if err := h.sessionStore.VerifyMFA(session.ID()); err != nil {
		log.Printf("verify mfa failed: %v", err)
		h.render(w, r, mfaVerifyModel{UnknownError: true})
		return
	}

	h.userBlocked.Reset(blockKey)
	h.events.RecordUser(r, domain.EventLoginMFA, domain.ResultSuccess, user, "")
	http.Redirect(w, r, utils.GetReturnURL(r, h.home), http.StatusFound)
}

func verifyAnyMFA(mfas []domain.MFACode, code string, now time.Time) bool {
	for _, mfa := range mfas {
		if cryptography.VerifyTOTP(mfa.Method(), mfa.Secret(), code, now) {
			return true
		}
	}

	return false
}

func (h *MFAVerifyHandler) render(w http.ResponseWriter, r *http.Request, model mfaVerifyModel) {
	model.Name = h.issuer
	model.CSRF = utils.GetCSRFToken(r)
	utils.RenderTemplate(w, h.template, model)
}

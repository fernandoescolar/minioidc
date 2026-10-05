package handlers

import (
	"html/template"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/internal/stores"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type MFACreateHandler struct {
	now            func() time.Time
	template       *template.Template
	issuer         string
	verifyEndpoint string
	mfaStore       domain.MFACodeStore
	sessionStore   domain.SessionStore
	userBlocked    domain.UserBlockedStore
	events         *domain.Recorder
	home           string
}

type mfaCreateModel struct {
	Name                    string
	IV                      string
	QRCode                  string
	InvalidVerificationCode bool
	TooManyAttempts         bool
	UnknownError            bool
	FormExpired             bool
	CSRF                    string
}

var _ http.Handler = (*MFACreateHandler)(nil)

func NewMfaCreateHandler(config *domain.Config, now func() time.Time, verifyEndpoint string) *MFACreateHandler {
	return &MFACreateHandler{
		now:            now,
		template:       utils.ParseTemplates(config.BasePath, config.BaseTemplateFilepath, config.MFACreateTemplateFilepath),
		issuer:         config.Name,
		verifyEndpoint: verifyEndpoint,
		mfaStore:       config.MFACodeStore,
		sessionStore:   config.SessionStore,
		userBlocked:    config.UserBlockedStore,
		events:         config.Events,
		home:           config.BasePath + "/",
	}
}

func (h *MFACreateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	session := utils.GetSession(r)
	if session == nil {
		utils.InternalServerError(w, "Failed to get session")
		return
	}

	// users with MFA must verify it: enrolling a new code would bypass it
	hasMFA, err := h.mfaStore.UserHasMFACodes(session.User().ID())
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	if hasMFA {
		location := h.verifyEndpoint + "?return_url=" + url.QueryEscape(utils.GetReturnURL(r, h.home))
		http.Redirect(w, r, location, http.StatusFound)
		return
	}

	if r.Method == http.MethodGet {
		h.getHTTP(w, r, session)
		return
	}

	h.postHTTP(w, r, session)
}

func (h *MFACreateHandler) getHTTP(w http.ResponseWriter, r *http.Request, session domain.Session) {
	secret, err := cryptography.NewTOTPSecret()
	if err != nil {
		utils.InternalServerError(w, "Failed to generate random secret")
		return
	}

	h.render(w, r, session, mfaCreateModel{IV: secret})
}

func (h *MFACreateHandler) postHTTP(w http.ResponseWriter, r *http.Request, session domain.Session) {
	if !utils.GetCSRFValid(r) {
		h.render(w, r, session, mfaCreateModel{IV: r.PostFormValue("verification_iv"), FormExpired: true})
		return
	}

	secret := r.PostFormValue("verification_iv")
	verificationCode := r.PostFormValue("verification_code")
	if secret == "" || verificationCode == "" {
		utils.Error(w, utils.InvalidRequest, "Missing verification_iv or verification_code", http.StatusBadRequest)
		return
	}

	now := h.now()
	blockKey := "mfa:" + session.User().ID()
	model := mfaCreateModel{IV: secret}
	if h.userBlocked.IsBlocked(blockKey, now) {
		model.TooManyAttempts = true
		h.render(w, r, session, model)
		return
	}

	if !cryptography.VerifyTOTP(cryptography.TOTPMethod, secret, verificationCode, now) {
		model.TooManyAttempts = h.userBlocked.AddFailedAttempt(blockKey, now)
		model.InvalidVerificationCode = !model.TooManyAttempts
		h.render(w, r, session, model)
		return
	}

	if _, err := h.mfaStore.NewMFACode(stores.CreateUID(), session.User(), secret, cryptography.TOTPMethod); err != nil {
		log.Printf("create mfa failed: %v", err)
		model.UnknownError = true
		h.render(w, r, session, model)
		return
	}

	if err := h.sessionStore.VerifyMFA(session.ID()); err != nil {
		log.Printf("verify mfa failed: %v", err)
		model.UnknownError = true
		h.render(w, r, session, model)
		return
	}

	h.userBlocked.Reset(blockKey)
	h.events.RecordUser(r, domain.EventMFAAdd, domain.ResultSuccess, session.User(), "enrolled in the login")
	http.Redirect(w, r, utils.GetReturnURL(r, h.home), http.StatusFound)
}

func (h *MFACreateHandler) render(w http.ResponseWriter, r *http.Request, session domain.Session, model mfaCreateModel) {
	model.Name = h.issuer
	model.CSRF = utils.GetCSRFToken(r)
	model.QRCode = cryptography.TOTPURI(h.issuer, session.User().Username(), model.IV)
	utils.RenderTemplate(w, h.template, model)
}

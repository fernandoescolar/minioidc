package handlers

import (
	"html/template"
	"log"
	"net/http"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type MFAVerifyHandler struct {
	templates    []string
	issuer       string
	mfaStore     domain.MFACodeStore
	sessionStore domain.SessionStore
}

type mfaVerifyModel struct {
	Name                    string
	InvalidVerificationCode bool
	UnknownError            bool
}

var _ http.Handler = (*MFACreateHandler)(nil)

func NewMfaVerifyHandler(config *domain.Config) *MFAVerifyHandler {
	return &MFAVerifyHandler{
		templates:    []string{config.BaseTemplateFilepath, config.MFAVerifyTemplateFilepath},
		issuer:       config.Name,
		mfaStore:     config.MFACodeStore,
		sessionStore: config.SessionStore,
	}
}

func (h *MFAVerifyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// create mfa form
	if r.Method == http.MethodGet {
		h.getHTTP(w, r)
		return
	}

	// handle mfa creation submission
	if r.Method == http.MethodPost {
		h.postHTTP(w, r)
		return
	}

	// not found
	http.NotFound(w, r)
}

func (h *MFAVerifyHandler) getHTTP(w http.ResponseWriter, r *http.Request) {
	model := mfaVerifyModel{
		Name:                    h.issuer,
		InvalidVerificationCode: false,
		UnknownError:            false,
	}

	h.showMfaVerifyForm(w, model)
}

func (h *MFAVerifyHandler) postHTTP(w http.ResponseWriter, r *http.Request) {
	session := utils.GetSession(r)
	if session == nil {
		utils.InternalServerError(w, "Failed to get session")
		return
	}

	r.ParseForm()
	verificationCode := r.FormValue("verification_code")
	if verificationCode == "" {
		utils.Error(w, "invalid_request", "Missing verification_code", http.StatusBadRequest)
		return
	}

	mfas, err := h.mfaStore.GetMFACodeByUserID(session.User().ID())
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	if len(mfas) == 0 {
		utils.InternalServerError(w, "Failed to get MFA codes")
		return
	}

	iv := mfas[0].Secret()
	topt := cryptography.NewTOTPDefault(iv)
	if !topt.Verify(verificationCode, 0, 1) {
		model := mfaVerifyModel{
			Name:                    h.issuer,
			InvalidVerificationCode: true,
			UnknownError:            false,
		}

		h.showMfaVerifyForm(w, model)
		return
	}

	if err := h.sessionStore.VerifyMFA(session.ID()); err != nil {
		log.Println("verify mfa failed: %w", err)
		model := mfaVerifyModel{
			Name:                    h.issuer,
			InvalidVerificationCode: false,
			UnknownError:            true,
		}
		h.showMfaVerifyForm(w, model)
		return
	}

	returnURL := utils.GetReturnURL(r)
	http.Redirect(w, r, returnURL, http.StatusFound)
}

func (h *MFAVerifyHandler) showMfaVerifyForm(w http.ResponseWriter, model mfaVerifyModel) {
	tmpl, err := template.ParseFiles(h.templates...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, model)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

package handlers

import (
	"html/template"
	"log"
	"net/http"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/internal/stores"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type MFACreateHandler struct {
	templates    []string
	issuer       string
	mfaStore     domain.MFACodeStore
	sessionStore domain.SessionStore
}

type mfaCreateModel struct {
	Name                    string
	IV                      string
	QRCode                  string
	InvalidVerificationCode bool
	UnknownError            bool
	CSRF                    string
}

var _ http.Handler = (*MFACreateHandler)(nil)

func NewMfaCreateHandler(config *domain.Config) *MFACreateHandler {
	return &MFACreateHandler{
		templates:    []string{config.BaseTemplateFilepath, config.MFACreateTemplateFilepath},
		issuer:       config.Name,
		mfaStore:     config.MFACodeStore,
		sessionStore: config.SessionStore,
	}
}

func (h *MFACreateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

func (h *MFACreateHandler) getHTTP(w http.ResponseWriter, r *http.Request) {
	session := utils.GetSession(r)
	if session == nil {
		utils.InternalServerError(w, "Failed to get session")
		return
	}

	iv, err := cryptography.RandomPassword(16)
	if err != nil {
		utils.InternalServerError(w, "Failed to generate random password")
		return
	}

	topt := cryptography.NewTOTPDefault(iv)
	qrCode := topt.Uri(h.issuer, session.User().Username())
	model := mfaCreateModel{
		Name:                    h.issuer,
		IV:                      iv,
		QRCode:                  qrCode,
		InvalidVerificationCode: false,
		UnknownError:            false,
	}

	h.showMfaCreateForm(w, r, model)
}

func (h *MFACreateHandler) postHTTP(w http.ResponseWriter, r *http.Request) {
	if !utils.GetCSRFValid(r) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	session := utils.GetSession(r)
	if session == nil {
		utils.InternalServerError(w, "Failed to get session")
		return
	}

	r.ParseForm()
	iv := r.FormValue("verification_iv")
	if iv == "" {
		utils.Error(w, "invalid_request", "Missing iv", http.StatusBadRequest)
		return
	}

	verificationCode := r.FormValue("verification_code")
	if verificationCode == "" {
		utils.Error(w, "invalid_request", "Missing verification_code", http.StatusBadRequest)
		return
	}

	topt := cryptography.NewTOTPDefault(iv)
	if !topt.Verify(verificationCode, 0, 1) {
		model := mfaCreateModel{
			Name:                    h.issuer,
			IV:                      iv,
			QRCode:                  topt.Uri(h.issuer, session.User().Username()),
			InvalidVerificationCode: true,
			UnknownError:            false,
		}

		h.showMfaCreateForm(w, r, model)
		return
	}

	_, err := h.mfaStore.NewMFACode(stores.CreateUID(), session.User(), iv, "topt")
	if err != nil {
		log.Println("create mfa failed: %w", err)
		model := mfaCreateModel{
			Name:                    h.issuer,
			IV:                      iv,
			QRCode:                  topt.Uri(h.issuer, session.User().Username()),
			InvalidVerificationCode: false,
			UnknownError:            true,
		}
		h.showMfaCreateForm(w, r, model)
		return
	}

	if err := h.sessionStore.VerifyMFA(session.ID()); err != nil {
		log.Println("verify mfa failed: %w", err)
		model := mfaCreateModel{
			Name:                    h.issuer,
			IV:                      iv,
			QRCode:                  topt.Uri(h.issuer, session.User().Username()),
			InvalidVerificationCode: false,
			UnknownError:            true,
		}
		h.showMfaCreateForm(w, r, model)
		return
	}

	returnURL := utils.GetReturnURL(r)
	http.Redirect(w, r, returnURL, http.StatusFound)
}

func (h *MFACreateHandler) showMfaCreateForm(w http.ResponseWriter, r *http.Request, model mfaCreateModel) {
	model.CSRF = utils.GetCSRFToken(r)
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

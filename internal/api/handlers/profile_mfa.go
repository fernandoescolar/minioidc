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

type ProfileMFAHandler struct {
	name      string
	issuer    string
	templates []string
	mfaStore  domain.MFACodeStore
}

type mfaEntry struct {
	ID     string
	Method string
}

type profileMFAModel struct {
	Name         string
	CSRF         string
	MFACodes     []mfaEntry
	IV           string
	QRCode       string
	InvalidCode  bool
	UnknownError bool
	Success      bool
}

var _ http.Handler = (*ProfileMFAHandler)(nil)

func NewProfileMFAHandler(config *domain.Config) *ProfileMFAHandler {
	return &ProfileMFAHandler{
		name:      config.Name,
		issuer:    config.Name,
		templates: []string{config.BaseTemplateFilepath, config.ProfileMFATemplateFilepath},
		mfaStore:  config.MFACodeStore,
	}
}

func (h *ProfileMFAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

func (h *ProfileMFAHandler) getHTTP(w http.ResponseWriter, r *http.Request) {
	session := utils.GetSession(r)
	if session == nil {
		utils.InternalServerError(w, "Failed to get session")
		return
	}

	csrf := utils.GetCSRFToken(r)
	model, err := h.buildModel(session, csrf, "", false, false, false)
	if err != nil {
		utils.InternalServerError(w, "Failed to load MFA codes")
		return
	}

	h.render(w, model)
}

func (h *ProfileMFAHandler) postHTTP(w http.ResponseWriter, r *http.Request) {
	if !utils.GetCSRFValid(r) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	session := utils.GetSession(r)
	if session == nil {
		utils.InternalServerError(w, "Failed to get session")
		return
	}

	csrf := utils.GetCSRFToken(r)
	r.ParseForm()
	action := r.FormValue("action")

	switch action {
	case "add":
		h.handleAdd(w, r, session, csrf)
	case "delete":
		h.handleDelete(w, r, session, csrf)
	default:
		http.Redirect(w, r, "/profile/mfa", http.StatusSeeOther)
	}
}

func (h *ProfileMFAHandler) handleAdd(w http.ResponseWriter, r *http.Request, session domain.Session, csrf string) {
	iv := r.FormValue("verification_iv")
	verificationCode := r.FormValue("verification_code")

	if iv == "" || verificationCode == "" {
		model, err := h.buildModel(session, csrf, "", false, false, false)
		if err != nil {
			utils.InternalServerError(w, "Failed to load MFA codes")
			return
		}
		h.render(w, model)
		return
	}

	topt := cryptography.NewTOTPDefault(iv)
	if !topt.Verify(verificationCode, 0, 1) {
		model, err := h.buildModel(session, csrf, iv, true, false, false)
		if err != nil {
			utils.InternalServerError(w, "Failed to load MFA codes")
			return
		}
		model.QRCode = topt.Uri(h.issuer, session.User().Username())
		h.render(w, model)
		return
	}

	_, err := h.mfaStore.NewMFACode(stores.CreateUID(), session.User(), iv, "topt")
	if err != nil {
		log.Printf("profile mfa add failed: %v", err)
		model, buildErr := h.buildModel(session, csrf, iv, false, true, false)
		if buildErr != nil {
			utils.InternalServerError(w, "Failed to load MFA codes")
			return
		}
		model.QRCode = topt.Uri(h.issuer, session.User().Username())
		h.render(w, model)
		return
	}

	// Redirect (PRG) to avoid double-submit
	http.Redirect(w, r, "/profile/mfa?success=1", http.StatusSeeOther)
}

func (h *ProfileMFAHandler) handleDelete(w http.ResponseWriter, r *http.Request, session domain.Session, csrf string) {
	id := r.FormValue("id")
	if id == "" {
		http.Redirect(w, r, "/profile/mfa", http.StatusSeeOther)
		return
	}

	if err := h.mfaStore.DeleteMFACode(id); err != nil {
		log.Printf("profile mfa delete failed: %v", err)
		model, buildErr := h.buildModel(session, csrf, "", false, true, false)
		if buildErr != nil {
			utils.InternalServerError(w, "Failed to load MFA codes")
			return
		}
		h.render(w, model)
		return
	}

	http.Redirect(w, r, "/profile/mfa", http.StatusSeeOther)
}

func (h *ProfileMFAHandler) buildModel(session domain.Session, csrf, iv string, invalidCode, unknownError, success bool) (profileMFAModel, error) {
	codes, err := h.mfaStore.GetMFACodeByUserID(session.User().ID())
	if err != nil {
		return profileMFAModel{}, err
	}

	entries := make([]mfaEntry, len(codes))
	for i, c := range codes {
		entries[i] = mfaEntry{ID: c.ID(), Method: c.Method()}
	}

	// Generate a fresh IV for the add form if none is in progress
	if iv == "" {
		newIV, err := cryptography.RandomPassword(16)
		if err != nil {
			return profileMFAModel{}, err
		}
		iv = newIV
	}

	qrCode := cryptography.NewTOTPDefault(iv).Uri(h.issuer, session.User().Username())

	return profileMFAModel{
		Name:         h.name,
		CSRF:         csrf,
		MFACodes:     entries,
		IV:           iv,
		QRCode:       qrCode,
		InvalidCode:  invalidCode,
		UnknownError: unknownError,
		Success:      success,
	}, nil
}

func (h *ProfileMFAHandler) render(w http.ResponseWriter, model profileMFAModel) {
	tmpl, err := template.ParseFiles(h.templates...)
	if err != nil {
		utils.InternalServerError(w, "Failed to parse template")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, model)
}

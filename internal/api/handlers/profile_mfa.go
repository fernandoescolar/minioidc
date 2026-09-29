package handlers

import (
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/internal/stores"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// ProfileMFAHandler lets the users add and remove their authenticator apps.
// When the user has authenticators, the changes require a code of one of
// them: a stolen session cannot replace the second factor of the user.
type ProfileMFAHandler struct {
	name        string
	now         func() time.Time
	template    *template.Template
	mfaStore    domain.MFACodeStore
	userBlocked domain.UserBlockedStore
	pageURL     string
}

type mfaEntry struct {
	ID     string
	Method string
}

type profileMFAModel struct {
	Name               string
	CSRF               string
	MFACodes           []mfaEntry
	IV                 string
	QRCode             string
	InvalidCode        bool
	InvalidCurrentCode bool
	TooManyAttempts    bool
	UnknownError       bool
	Success            bool
	FormExpired        bool
}

var _ http.Handler = (*ProfileMFAHandler)(nil)

func NewProfileMFAHandler(config *domain.Config, now func() time.Time, pageURL string) *ProfileMFAHandler {
	return &ProfileMFAHandler{
		name:        config.Name,
		now:         now,
		template:    utils.ParseTemplates(config.BasePath, config.BaseTemplateFilepath, config.ProfileMFATemplateFilepath),
		mfaStore:    config.MFACodeStore,
		userBlocked: config.UserBlockedStore,
		pageURL:     pageURL,
	}
}

func (h *ProfileMFAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session := utils.GetSession(r)
	if session == nil {
		utils.InternalServerError(w, "Failed to get session")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.render(w, r, session, profileMFAModel{Success: r.URL.Query().Get("success") == "1"})
	case http.MethodPost:
		h.postHTTP(w, r, session)
	default:
		http.NotFound(w, r)
	}
}

func (h *ProfileMFAHandler) postHTTP(w http.ResponseWriter, r *http.Request, session domain.Session) {
	if !utils.GetCSRFValid(r) {
		h.render(w, r, session, profileMFAModel{IV: r.PostFormValue("verification_iv"), FormExpired: true})
		return
	}

	now := h.now()
	userID := session.User().ID()
	blockKey := "mfa:" + userID
	if h.userBlocked.IsBlocked(blockKey, now) {
		h.render(w, r, session, profileMFAModel{TooManyAttempts: true})
		return
	}

	codes, err := h.mfaStore.GetMFACodeByUserID(userID)
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	// step up: the changes require a code of a current authenticator
	if len(codes) > 0 && !verifyAnyMFA(codes, r.PostFormValue("current_code"), now) {
		model := profileMFAModel{IV: r.PostFormValue("verification_iv")}
		model.TooManyAttempts = h.userBlocked.AddFailedAttempt(blockKey, now)
		model.InvalidCurrentCode = !model.TooManyAttempts
		h.render(w, r, session, model)
		return
	}

	switch r.PostFormValue("action") {
	case "add":
		secret := r.PostFormValue("verification_iv")
		if secret == "" || !cryptography.VerifyTOTP(cryptography.TOTPMethod, secret, r.PostFormValue("verification_code"), now) {
			model := profileMFAModel{IV: secret}
			model.TooManyAttempts = h.userBlocked.AddFailedAttempt(blockKey, now)
			model.InvalidCode = !model.TooManyAttempts
			h.render(w, r, session, model)
			return
		}

		if _, err := h.mfaStore.NewMFACode(stores.CreateUID(), session.User(), secret, cryptography.TOTPMethod); err != nil {
			log.Printf("profile mfa add failed: %v", err)
			h.render(w, r, session, profileMFAModel{UnknownError: true})
			return
		}
	case "delete":
		if err := h.mfaStore.DeleteMFACode(userID, r.PostFormValue("id")); err != nil {
			h.render(w, r, session, profileMFAModel{UnknownError: true})
			return
		}
	default:
		http.Redirect(w, r, h.pageURL, http.StatusSeeOther)
		return
	}

	h.userBlocked.Reset(blockKey)
	// Post/Redirect/Get: a reload does not submit the form again
	http.Redirect(w, r, h.pageURL+"?success=1", http.StatusSeeOther)
}

func (h *ProfileMFAHandler) render(w http.ResponseWriter, r *http.Request, session domain.Session, model profileMFAModel) {
	codes, err := h.mfaStore.GetMFACodeByUserID(session.User().ID())
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	for _, c := range codes {
		model.MFACodes = append(model.MFACodes, mfaEntry{ID: c.ID(), Method: c.Method()})
	}

	// a new secret for the add form, unless one is in progress
	if model.IV == "" {
		if model.IV, err = cryptography.NewTOTPSecret(); err != nil {
			utils.InternalServerError(w, err.Error())
			return
		}
	}

	model.Name = h.name
	model.CSRF = utils.GetCSRFToken(r)
	model.QRCode = cryptography.TOTPURI(h.name, session.User().Username(), model.IV)
	utils.RenderTemplate(w, h.template, model)
}

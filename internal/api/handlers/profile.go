package handlers

import (
	"html/template"
	"net/http"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// ProfileHandler is the page of the logged in user
type ProfileHandler struct {
	name       string
	template   *template.Template
	userStore  domain.UserStore
	mfaStore   domain.MFACodeStore
	passkeys   domain.PasskeyStore
	adminGroup string
	adminURL   string
}

type profileModel struct {
	Name              string
	Username          string
	DisplayName       string
	Email             string
	HasMFA            bool
	CanChangePassword bool
	// PasskeysEnabled shows the passkeys, and Passkeys is their number
	PasskeysEnabled bool
	Passkeys        int
	// AdminURL is the admin web, only for the administrators
	AdminURL string
}

var _ http.Handler = (*ProfileHandler)(nil)

func NewProfileHandler(config *domain.Config) *ProfileHandler {
	h := &ProfileHandler{
		name:      config.Name,
		template:  utils.ParseTemplates(config.BasePath, config.BaseTemplateFilepath, config.ProfileTemplateFilepath),
		userStore: config.UserStore,
		mfaStore:  config.MFACodeStore,
	}
	if config.PasskeysEnabled {
		h.passkeys = config.PasskeyStore
	}
	if config.AdminEnabled {
		h.adminGroup = config.AdminGroup
		h.adminURL = config.BasePath + "/admin/"
	}

	return h
}

func (h *ProfileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	session := utils.GetSession(r)
	if session == nil {
		utils.InternalServerError(w, "Failed to get session")
		return
	}

	user := session.User()
	data := user.Data()
	hasMFA, _ := h.mfaStore.UserHasMFACodes(user.ID())
	model := profileModel{
		Name:              h.name,
		Username:          data.PreferredUsername,
		DisplayName:       data.Name,
		Email:             data.Email,
		HasMFA:            hasMFA,
		CanChangePassword: canChangePassword(h.userStore, user),
	}
	if h.passkeys != nil {
		passkeys, _ := h.passkeys.ListPasskeys(user.ID())
		model.PasskeysEnabled = true
		model.Passkeys = len(passkeys)
	}
	if h.adminURL != "" && user.InGroup(h.adminGroup) {
		model.AdminURL = h.adminURL
	}

	utils.RenderTemplate(w, h.template, model)
}

// canChangePassword is true when the store can change the password of the
// user (not in LDAP) and the user has a local password
func canChangePassword(store domain.UserStore, user domain.User) bool {
	_, ok := store.(domain.PasswordUpdater)
	return ok && user.Data().PasswordHash != ""
}

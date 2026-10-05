package handlers

import (
	"encoding/json"
	"errors"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/internal/passkeys"
	"github.com/fernandoescolar/minioidc/internal/stores"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

const (
	// PasskeyHeader protects the JSON endpoints of the passkeys from CSRF: the
	// browsers only send custom headers to other sites after a CORS preflight
	PasskeyHeader = "X-Minioidc-Passkey"
	// passkeyReauthAge is how recent the login must be to add or remove passkeys
	passkeyReauthAge = 10 * time.Minute
	maxPasskeyBody   = 64 << 10
)

// passkeyRequest checks that the request is a POST of the passkey scripts
func passkeyRequest(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return false
	}

	if r.Header.Get(PasskeyHeader) == "" {
		writePasskeyError(w, http.StatusForbidden, "missing "+PasskeyHeader+" header")
		return false
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxPasskeyBody)
	return true
}

func writePasskeyJSON(w http.ResponseWriter, value interface{}) {
	data, err := json.Marshal(value)
	if err != nil {
		utils.InternalServerError(w, err.Error())
		return
	}

	utils.JSON(w, data)
}

func writePasskeyError(w http.ResponseWriter, status int, message string) {
	data, _ := json.Marshal(map[string]string{"error": message})
	utils.NoCache(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

// passkeyErrorMessage is the message for the user: the details are logged
func passkeyErrorMessage(err error) string {
	switch {
	case errors.Is(err, passkeys.ErrInvalidChallenge), errors.Is(err, passkeys.ErrTooManyRequests), errors.Is(err, passkeys.ErrClonedPasskey):
		return err.Error()
	default:
		log.Printf("Passkey: %v", err)
		return "The passkey could not be verified"
	}
}

// PasskeyLoginHandler signs in the users with a passkey, without a password.
// A passkey verifies the user (biometrics or PIN), so it is also the MFA.
type PasskeyLoginHandler struct {
	now           func() time.Time
	service       *passkeys.Service
	sessionStore  domain.SessionStore
	userStates    domain.UserStateStore
	events        *domain.Recorder
	sessionTTL    time.Duration
	masterKey     string
	secureCookies bool
	home          string
}

func NewPasskeyLoginHandler(config *domain.Config, now func() time.Time, service *passkeys.Service) *PasskeyLoginHandler {
	return &PasskeyLoginHandler{
		now:           now,
		service:       service,
		sessionStore:  config.SessionStore,
		userStates:    config.UserStateStore,
		events:        config.Events,
		sessionTTL:    config.SessionTTL,
		masterKey:     config.MasterKey,
		secureCookies: config.UseSecureCookie,
		home:          config.BasePath + "/",
	}
}

// Begin returns the options of navigator.credentials.get()
func (h *PasskeyLoginHandler) Begin() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !passkeyRequest(w, r) {
			return
		}

		options, err := h.service.BeginLogin()
		if err != nil {
			writePasskeyError(w, http.StatusServiceUnavailable, passkeyErrorMessage(err))
			return
		}

		writePasskeyJSON(w, options)
	})
}

// Finish verifies the passkey and creates the session. It answers the URL to
// continue: the return_url of the login page.
func (h *PasskeyLoginHandler) Finish() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !passkeyRequest(w, r) {
			return
		}

		user, err := h.service.FinishLogin(r.Body)
		if err != nil {
			message := passkeyErrorMessage(err)
			// a cloned passkey has a user; the other failures do not
			h.events.RecordUser(r, domain.EventLoginPasskey, domain.ResultFailure, user, message)
			writePasskeyError(w, http.StatusBadRequest, message)
			return
		}

		now := h.now()
		switch err := domain.CheckSignIn(h.userStates, user.ID(), now); {
		case errors.Is(err, domain.ErrAccountDisabled):
			h.events.RecordUser(r, domain.EventLoginPasskey, domain.ResultFailure, user, err.Error())
			writePasskeyError(w, http.StatusForbidden, "This account is disabled. Contact the administrator.")
			return
		case errors.Is(err, domain.ErrAccountLocked):
			h.events.RecordUser(r, domain.EventLoginPasskey, domain.ResultFailure, user, err.Error())
			writePasskeyError(w, http.StatusForbidden, "This account is locked. Contact the administrator.")
			return
		case err != nil:
			utils.InternalServerError(w, err.Error())
			return
		}

		expiresAt := now.Add(h.sessionTTL)
		session, err := h.sessionStore.NewPasskeySession(stores.CreateUID(), user, now, expiresAt)
		if err == nil {
			err = utils.SetSessionCookie(w, h.masterKey, session.ID(), expiresAt, h.secureCookies)
		}
		if err != nil {
			utils.InternalServerError(w, err.Error())
			return
		}

		h.events.RecordUser(r, domain.EventLoginPasskey, domain.ResultSuccess, user, "")
		writePasskeyJSON(w, map[string]string{"redirect": utils.GetReturnURL(r, h.home)})
	})
}

// ProfilePasskeysHandler lets the users add, rename and remove their passkeys.
// Adding and removing them requires a recent login.
type ProfilePasskeysHandler struct {
	name     string
	now      func() time.Time
	template *template.Template
	service  *passkeys.Service
	store    domain.PasskeyStore
	events   *domain.Recorder
	pageURL  string
	loginURL string
}

type passkeyView struct {
	ID         string
	Name       string
	CreatedAt  string
	LastUsedAt string
}

type profilePasskeysModel struct {
	Name       string
	CSRF       string
	Passkeys   []passkeyView
	RecentAuth bool
	ReauthURL  string

	Added        bool
	Renamed      bool
	Deleted      bool
	NotFound     bool
	UnknownError bool
	FormExpired  bool
}

func NewProfilePasskeysHandler(config *domain.Config, now func() time.Time, service *passkeys.Service, pageURL, loginURL string) *ProfilePasskeysHandler {
	return &ProfilePasskeysHandler{
		name:     config.Name,
		now:      now,
		template: utils.ParseTemplates(config.BasePath, config.BaseTemplateFilepath, config.ProfilePasskeysTemplateFilepath),
		service:  service,
		store:    config.PasskeyStore,
		events:   config.Events,
		pageURL:  pageURL,
		loginURL: loginURL,
	}
}

func (h *ProfilePasskeysHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session := utils.GetSession(r)
	if session == nil {
		utils.InternalServerError(w, "Failed to get session")
		return
	}

	switch r.Method {
	case http.MethodGet:
		query := r.URL.Query()
		h.render(w, http.StatusOK, session, profilePasskeysModel{
			CSRF:    utils.GetCSRFToken(r),
			Added:   query.Has("added"),
			Renamed: query.Has("renamed"),
			Deleted: query.Has("deleted"),
		})
	case http.MethodPost:
		h.postHTTP(w, r, session)
	default:
		http.NotFound(w, r)
	}
}

func (h *ProfilePasskeysHandler) postHTTP(w http.ResponseWriter, r *http.Request, session domain.Session) {
	model := profilePasskeysModel{CSRF: utils.GetCSRFToken(r)}
	if !utils.GetCSRFValid(r) {
		model.FormExpired = true
		h.render(w, http.StatusBadRequest, session, model)
		return
	}

	// the stores only change the passkeys of the user
	userID := session.User().ID()
	id := r.PostFormValue("id")
	var (
		err    error
		result string
	)
	switch r.PostFormValue("action") {
	case "rename":
		result = "renamed"
		err = h.store.RenamePasskey(userID, id, passkeys.CleanName(r.PostFormValue("name"), 1))
	case "delete":
		// a stolen session cannot remove the passkeys of the user
		if !h.recentAuth(session) {
			h.render(w, http.StatusForbidden, session, model)
			return
		}

		result = "deleted"
		err = h.store.DeletePasskey(userID, id)
		if err == nil {
			h.events.RecordUser(r, domain.EventPasskeyRemove, domain.ResultSuccess, session.User(), "")
		}
	default:
		http.Error(w, "Unknown action", http.StatusBadRequest)
		return
	}

	if err != nil {
		model.NotFound = true
		h.render(w, http.StatusOK, session, model)
		return
	}

	// Post/Redirect/Get: a reload does not submit the form again
	http.Redirect(w, r, h.pageURL+"?"+result+"=1", http.StatusSeeOther)
}

// RegisterBegin returns the options of navigator.credentials.create()
func (h *ProfilePasskeysHandler) RegisterBegin() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := h.registrationSession(w, r)
		if !ok {
			return
		}

		options, err := h.service.BeginRegistration(session.User())
		if err != nil {
			writePasskeyError(w, http.StatusServiceUnavailable, passkeyErrorMessage(err))
			return
		}

		writePasskeyJSON(w, options)
	})
}

// RegisterFinish verifies the new passkey and stores it. The name is in the
// name query parameter.
func (h *ProfilePasskeysHandler) RegisterFinish() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := h.registrationSession(w, r)
		if !ok {
			return
		}

		passkey, err := h.service.FinishRegistration(session.User(), r.URL.Query().Get("name"), r.Body)
		if err != nil {
			writePasskeyError(w, http.StatusBadRequest, passkeyErrorMessage(err))
			return
		}

		h.events.RecordUser(r, domain.EventPasskeyAdd, domain.ResultSuccess, session.User(), passkey.Name)

		writePasskeyJSON(w, map[string]string{"redirect": h.pageURL + "?added=1"})
	})
}

// registrationSession checks the request and that the login is recent: a
// stolen session cannot add a passkey to keep the access
func (h *ProfilePasskeysHandler) registrationSession(w http.ResponseWriter, r *http.Request) (domain.Session, bool) {
	if !passkeyRequest(w, r) {
		return nil, false
	}

	session := utils.GetSession(r)
	if session == nil {
		writePasskeyError(w, http.StatusUnauthorized, "Sign in again")
		return nil, false
	}

	if !h.recentAuth(session) {
		writePasskeyError(w, http.StatusForbidden, "Sign in again to add a passkey")
		return nil, false
	}

	return session, true
}

func (h *ProfilePasskeysHandler) recentAuth(session domain.Session) bool {
	authTime := session.AuthTime()
	return !authTime.IsZero() && h.now().Sub(authTime) <= passkeyReauthAge
}

func (h *ProfilePasskeysHandler) render(w http.ResponseWriter, status int, session domain.Session, model profilePasskeysModel) {
	user := session.User()
	stored, err := h.store.ListPasskeys(user.ID())
	if err != nil {
		log.Printf("Passkeys: %v", err)
		model.UnknownError = true
	}

	for _, passkey := range stored {
		view := passkeyView{ID: passkey.ID, Name: passkey.Name, CreatedAt: passkey.CreatedAt.Format("Jan 2, 2006")}
		if !passkey.LastUsedAt.IsZero() {
			view.LastUsedAt = passkey.LastUsedAt.Format("Jan 2, 2006")
		}
		model.Passkeys = append(model.Passkeys, view)
	}

	model.Name = h.name
	model.RecentAuth = h.recentAuth(session)
	model.ReauthURL = h.loginURL + "?" + url.Values{"return_url": {h.pageURL}, "login_hint": {user.Data().PreferredUsername}}.Encode()
	utils.RenderTemplateStatus(w, status, h.template, model)
}

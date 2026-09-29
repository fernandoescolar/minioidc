// Package admin serves the admin web and its JSON API at <issuer>/admin/.
// Only the members of the admin group (with the MFA verified, if required) can use them.
package admin

import (
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/handlers"
	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// CSRFHeader must be sent in the requests that change data. Browsers cannot
// send custom headers to other sites without CORS, and the API has no CORS.
const CSRFHeader = "X-Minioidc-Admin"

//go:embed all:ui
var uiFiles embed.FS

type contextKey string

const adminUserKey contextKey = "admin_user"

// Handler serves the admin web and API
type Handler struct {
	now           func() time.Time
	masterKey     string
	name          string
	adminGroup    string
	issuer        string
	allowImplicit bool
	allowPassword bool
	sessionStore  domain.SessionStore
	userStore     domain.UserStore
	users         domain.UserAdminStore // nil when the users are read only (LDAP, YAML)
	clients       domain.ClientAdminStore
	grantStore    domain.GrantStore
	mfaStore      domain.MFACodeStore
	userBlocked   domain.UserBlockedStore
	assertions    domain.ClientAssertionStore
	ui            fs.FS
	errors        *handlers.ErrorPage
	mux           *http.ServeMux
}

var _ http.Handler = (*Handler)(nil)

// NewHandler creates the handler. It must be mounted at <base path>/admin with the prefix stripped.
func NewHandler(config *domain.Config, now func() time.Time) (*Handler, error) {
	clients, ok := config.ClientStore.(domain.ClientAdminStore)
	if !ok {
		return nil, errors.New("the admin web requires a client store that can be managed (sqlite use_in_clients)")
	}

	users, _ := config.UserStore.(domain.UserAdminStore)
	h := &Handler{
		now:           now,
		masterKey:     config.MasterKey,
		name:          config.Name,
		adminGroup:    config.AdminGroup,
		issuer:        config.Issuer,
		allowImplicit: config.AllowImplicitFlow,
		allowPassword: config.AllowPasswordGrant,
		sessionStore:  config.SessionStore,
		userStore:     config.UserStore,
		users:         users,
		clients:       clients,
		grantStore:    config.GrantStore,
		mfaStore:      config.MFACodeStore,
		userBlocked:   config.UserBlockedStore,
		assertions:    config.ClientAssertionStore,
		ui:            uiFS(),
		errors:        handlers.NewErrorPage(config),
		mux:           http.NewServeMux(),
	}

	h.routes()
	return h, nil
}

// uiFS returns the built web (ui/dist) or a placeholder page when it has not been built
func uiFS() fs.FS {
	if dist, err := fs.Sub(uiFiles, "ui/dist"); err == nil {
		if _, err := fs.Stat(dist, "index.html"); err == nil {
			return dist
		}
	}

	placeholder, _ := fs.Sub(uiFiles, "ui/placeholder")
	return placeholder
}

func (h *Handler) routes() {
	api := func(pattern string, handler func(http.ResponseWriter, *http.Request)) {
		h.mux.Handle(pattern, h.requireAdmin(http.HandlerFunc(handler)))
	}

	api("GET /api/info", h.info)

	api("GET /api/users", h.listUsers)
	api("POST /api/users", h.createUser)
	api("GET /api/users/{id}", h.getUser)
	api("PUT /api/users/{id}", h.updateUser)
	api("DELETE /api/users/{id}", h.deleteUser)
	api("GET /api/users/{id}/sessions", h.listSessions)
	api("DELETE /api/users/{id}/sessions", h.deleteSessions)
	api("DELETE /api/users/{id}/sessions/{session}", h.deleteSession)
	api("DELETE /api/users/{id}/mfa", h.resetMFA)
	api("POST /api/users/{id}/unblock", h.unblockUser)

	api("GET /api/clients", h.listClients)
	api("POST /api/clients", h.createClient)
	api("GET /api/clients/{id}", h.getClient)
	api("PUT /api/clients/{id}", h.updateClient)
	api("DELETE /api/clients/{id}", h.deleteClient)
	api("POST /api/clients/{id}/secret", h.rotateClientSecret)
	api("DELETE /api/clients/{id}/tokens", h.revokeClientTokens)

	api("POST /api/maintenance/purge", h.purgeExpired)
	api("POST /api/maintenance/logout-all", h.logoutAll)

	h.mux.Handle("GET /", h.requireAdmin(http.HandlerFunc(h.serveUI)))
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// requireAdmin checks the session cookie: the user must be an administrator
// with the MFA verified. The API answers with JSON errors and the web with
// the login redirect (done by the SessionAuthorized middleware) or a 403 page.
func (h *Handler) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isAPI := strings.HasPrefix(r.URL.Path, "/api/")
		utils.NoCache(w)

		user, status := h.currentAdmin(r)
		if status != http.StatusOK {
			if isAPI {
				writeError(w, status, http.StatusText(status))
			} else {
				h.errors.Render(w, http.StatusForbidden, "Access denied", "Only the administrators can use the admin web.")
			}
			return
		}

		if isAPI && r.Method != http.MethodGet && r.Header.Get(CSRFHeader) == "" {
			writeError(w, http.StatusForbidden, "missing "+CSRFHeader+" header")
			return
		}

		next.ServeHTTP(w, r.WithContext(contextWithAdmin(r, user)))
	})
}

func (h *Handler) currentAdmin(r *http.Request) (domain.User, int) {
	sessionID := utils.GetSessionIDFromCookie(r, h.masterKey)
	if sessionID == "" {
		return nil, http.StatusUnauthorized
	}

	session, err := h.sessionStore.GetSessionByID(sessionID)
	if err != nil || session.HasExpired(h.now()) || session.MFARequired() {
		return nil, http.StatusUnauthorized
	}

	if !session.User().InGroup(h.adminGroup) {
		return nil, http.StatusForbidden
	}

	return session.User(), http.StatusOK
}

func (h *Handler) serveUI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}

	if _, err := fs.Stat(h.ui, path); err != nil {
		http.NotFound(w, r)
		return
	}

	// the assets have a hash in their names: they can be cached
	if strings.HasPrefix(path, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Del("Pragma")
	}

	http.ServeFileFS(w, r, h.ui, path)
}

func (h *Handler) info(w http.ResponseWriter, r *http.Request) {
	user := adminFromContext(r)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name":           h.name,
		"issuer":         h.issuer,
		"admin_group":    h.adminGroup,
		"users_readonly": h.users == nil,
		// the discouraged flows must be enabled in the configuration
		"allow_implicit_flow":  h.allowImplicit,
		"allow_password_grant": h.allowPassword,
		"me": map[string]string{
			"subject":            user.ID(),
			"preferred_username": user.Data().PreferredUsername,
			"name":               user.Data().Name,
		},
	})
}

func (h *Handler) purgeExpired(w http.ResponseWriter, _ *http.Request) {
	now := h.now()
	h.sessionStore.CleanExpired()
	h.grantStore.CleanExpired()
	h.userBlocked.CleanExpired(now)
	h.assertions.CleanExpired(now)
	log.Println("admin: expired sessions, tokens and blocks purged")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) logoutAll(w http.ResponseWriter, _ *http.Request) {
	if err := h.sessionStore.DeleteAllSessions(); err != nil {
		writeInternalError(w, err)
		return
	}

	log.Println("admin: all the sessions have been closed")
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("admin: writing response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeInternalError(w http.ResponseWriter, err error) {
	log.Printf("admin: %v", err)
	writeError(w, http.StatusInternalServerError, "internal server error")
}

// readJSON decodes the body, rejecting unknown fields
func readJSON(w http.ResponseWriter, r *http.Request, target interface{}) bool {
	const maxBody = 1 << 20
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}

	return true
}

package admin

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/google/uuid"
)

const minPasswordLength = 8

type userDTO struct {
	Subject           string   `json:"subject"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Name              string   `json:"name"`
	GivenName         string   `json:"given_name"`
	FamilyName        string   `json:"family_name"`
	Phone             string   `json:"phone"`
	Address           string   `json:"address"`
	Groups            []string `json:"groups"`
	HasPassword       bool     `json:"has_password"`
	HasMFA            bool     `json:"has_mfa"`
	Blocked           bool     `json:"blocked"`
	Admin             bool     `json:"admin"`
}

// userInput is the body to create or update a user. An empty password keeps the current one.
type userInput struct {
	Subject           string   `json:"subject"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Name              string   `json:"name"`
	GivenName         string   `json:"given_name"`
	FamilyName        string   `json:"family_name"`
	Phone             string   `json:"phone"`
	Address           string   `json:"address"`
	Groups            []string `json:"groups"`
	Password          string   `json:"password"`
}

type sessionDTO struct {
	// ID is a hash of the session ID: the session ID itself is a credential
	ID          string    `json:"id"`
	AuthTime    time.Time `json:"auth_time"`
	ExpiresAt   time.Time `json:"expires_at"`
	AuthMethods []string  `json:"auth_methods"`
	MFAPending  bool      `json:"mfa_pending"`
	Current     bool      `json:"current"`
}

func (h *Handler) userDTO(data domain.UserData) userDTO {
	hasMFA, _ := h.mfaStore.UserHasMFACodes(data.Subject)
	user := domain.NewUser(data)
	return userDTO{
		Subject:           data.Subject,
		PreferredUsername: data.PreferredUsername,
		Email:             data.Email,
		EmailVerified:     data.EmailVerified,
		Name:              data.Name,
		GivenName:         data.GivenName,
		FamilyName:        data.FamilyName,
		Phone:             data.Phone,
		Address:           data.Address,
		Groups:            nonNil(data.Groups),
		HasPassword:       data.PasswordHash != "",
		HasMFA:            hasMFA,
		Blocked:           h.userBlocked.IsBlocked(loginBlockKey(data.PreferredUsername), h.now()),
		Admin:             user.InGroup(h.adminGroup),
	}
}

// writableUsers returns false (and writes the error) when the users cannot be changed
func (h *Handler) writableUsers(w http.ResponseWriter) bool {
	if h.users == nil {
		writeError(w, http.StatusMethodNotAllowed, "the users are read only: they are managed in the configuration or in LDAP")
		return false
	}

	return true
}

func (h *Handler) listUsers(w http.ResponseWriter, _ *http.Request) {
	if h.users == nil {
		// read only stores cannot list their users
		writeJSON(w, http.StatusOK, []userDTO{})
		return
	}

	users, err := h.users.ListUsers()
	if err != nil {
		writeInternalError(w, err)
		return
	}

	result := make([]userDTO, 0, len(users))
	for _, u := range users {
		result = append(result, h.userDTO(u))
	}

	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) getUser(w http.ResponseWriter, r *http.Request) {
	user, ok := h.findUser(w, r)
	if ok {
		writeJSON(w, http.StatusOK, h.userDTO(user.Data()))
	}
}

func (h *Handler) findUser(w http.ResponseWriter, r *http.Request) (domain.User, bool) {
	user, err := h.userStore.GetUserByID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return nil, false
	}

	return user, true
}

func (h *Handler) createUser(w http.ResponseWriter, r *http.Request) {
	if !h.writableUsers(w) {
		return
	}

	var input userInput
	if !readJSON(w, r, &input) {
		return
	}

	if input.Subject == "" {
		input.Subject = uuid.NewString()
	}

	if len(input.Password) < minPasswordLength {
		writeError(w, http.StatusBadRequest, "the password must have at least 8 characters")
		return
	}

	data, ok := h.userData(w, input)
	if !ok {
		return
	}

	if _, err := h.userStore.GetUserByID(data.Subject); err == nil {
		writeError(w, http.StatusConflict, "a user with this subject already exists")
		return
	}

	if _, err := h.users.NewUser(data); err != nil {
		writeStoreError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, h.userDTO(data))
}

func (h *Handler) updateUser(w http.ResponseWriter, r *http.Request) {
	if !h.writableUsers(w) {
		return
	}

	current, ok := h.findUser(w, r)
	if !ok {
		return
	}

	var input userInput
	if !readJSON(w, r, &input) {
		return
	}

	input.Subject = current.ID()
	if input.Password != "" && len(input.Password) < minPasswordLength {
		writeError(w, http.StatusBadRequest, "the password must have at least 8 characters")
		return
	}

	data, ok := h.userData(w, input)
	if !ok {
		return
	}

	// an administrator cannot remove their own admin rights (they would be locked out)
	if current.ID() == adminFromContext(r).ID() && !domain.NewUser(data).InGroup(h.adminGroup) {
		writeError(w, http.StatusBadRequest, "you cannot remove yourself from the admin group")
		return
	}

	if err := h.users.UpdateUser(data); err != nil {
		writeStoreError(w, err)
		return
	}

	// the login block is by username: renaming the user must not unblock it
	updated, _ := h.userStore.GetUserByID(data.Subject)
	writeJSON(w, http.StatusOK, h.userDTO(updated.Data()))
}

// userData validates the input and hashes the password
func (h *Handler) userData(w http.ResponseWriter, input userInput) (domain.UserData, bool) {
	input.PreferredUsername = strings.TrimSpace(input.PreferredUsername)
	if input.PreferredUsername == "" {
		writeError(w, http.StatusBadRequest, "the username (preferred_username) is required")
		return domain.UserData{}, false
	}

	groups := []string{}
	seen := map[string]bool{}
	for _, g := range input.Groups {
		g = strings.TrimSpace(g)
		if g != "" && !seen[g] {
			seen[g] = true
			groups = append(groups, g)
		}
	}
	sort.Strings(groups)

	passwordHash := ""
	if input.Password != "" {
		var err error
		if passwordHash, err = cryptography.HashPassword(input.Password); err != nil {
			writeInternalError(w, err)
			return domain.UserData{}, false
		}
	}

	return domain.UserData{
		Subject:           input.Subject,
		PreferredUsername: input.PreferredUsername,
		Email:             strings.TrimSpace(input.Email),
		EmailVerified:     input.EmailVerified,
		Name:              input.Name,
		GivenName:         input.GivenName,
		FamilyName:        input.FamilyName,
		Phone:             input.Phone,
		Address:           input.Address,
		Groups:            groups,
		PasswordHash:      passwordHash,
	}, true
}

func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request) {
	if !h.writableUsers(w) {
		return
	}

	user, ok := h.findUser(w, r)
	if !ok {
		return
	}

	if user.ID() == adminFromContext(r).ID() {
		writeError(w, http.StatusBadRequest, "you cannot delete yourself")
		return
	}

	h.sessionStore.DeleteUserSessions(user.ID())
	h.mfaStore.DeleteUserMFACodes(user.ID())
	if err := h.users.DeleteUser(user.ID()); err != nil {
		writeStoreError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listSessions(w http.ResponseWriter, r *http.Request) {
	user, ok := h.findUser(w, r)
	if !ok {
		return
	}

	sessions, err := h.sessionStore.ListUserSessions(user.ID(), h.now())
	if err != nil {
		writeInternalError(w, err)
		return
	}

	currentID := h.currentSessionHash(r)
	result := make([]sessionDTO, 0, len(sessions))
	for _, s := range sessions {
		id := cryptography.SHA256(s.ID())
		result = append(result, sessionDTO{
			ID:          id,
			AuthTime:    s.AuthTime(),
			ExpiresAt:   s.ExpiresAt(),
			AuthMethods: s.AuthMethods(),
			MFAPending:  s.MFARequired(),
			Current:     id == currentID,
		})
	}

	sort.Slice(result, func(i, j int) bool { return result[i].AuthTime.After(result[j].AuthTime) })
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) currentSessionHash(r *http.Request) string {
	return cryptography.SHA256(sessionIDFromRequest(r, h.masterKey))
}

func (h *Handler) deleteSessions(w http.ResponseWriter, r *http.Request) {
	user, ok := h.findUser(w, r)
	if !ok {
		return
	}

	// the access tokens are rejected as soon as their session does not exist,
	// and the refresh tokens cannot be used without it
	h.sessionStore.DeleteUserSessions(user.ID())
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) deleteSession(w http.ResponseWriter, r *http.Request) {
	user, ok := h.findUser(w, r)
	if !ok {
		return
	}

	sessions, err := h.sessionStore.ListUserSessions(user.ID(), h.now())
	if err != nil {
		writeInternalError(w, err)
		return
	}

	for _, s := range sessions {
		if cryptography.SHA256(s.ID()) == r.PathValue("session") {
			if err := h.sessionStore.DeleteSession(s.ID()); err != nil {
				writeInternalError(w, err)
				return
			}

			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	writeError(w, http.StatusNotFound, "session not found")
}

func (h *Handler) resetMFA(w http.ResponseWriter, r *http.Request) {
	user, ok := h.findUser(w, r)
	if !ok {
		return
	}

	// the user will enroll a new authenticator in the next login
	h.mfaStore.DeleteUserMFACodes(user.ID())
	h.userBlocked.Reset(mfaBlockKey(user.ID()))
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) unblockUser(w http.ResponseWriter, r *http.Request) {
	user, ok := h.findUser(w, r)
	if !ok {
		return
	}

	h.userBlocked.Reset(loginBlockKey(user.Data().PreferredUsername))
	h.userBlocked.Reset(mfaBlockKey(user.ID()))
	w.WriteHeader(http.StatusNoContent)
}

// the keys used by the login and MFA handlers to count the failed attempts
func loginBlockKey(username string) string {
	return "login:" + strings.ToLower(username)
}

func mfaBlockKey(userID string) string {
	return "mfa:" + userID
}

func writeStoreError(w http.ResponseWriter, err error) {
	message := err.Error()
	switch {
	case strings.Contains(message, "UNIQUE constraint failed"):
		writeError(w, http.StatusConflict, "the username or the id already exists")
	case strings.Contains(message, "not found"):
		writeError(w, http.StatusNotFound, message)
	default:
		writeError(w, http.StatusBadRequest, message)
	}
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}

	return values
}

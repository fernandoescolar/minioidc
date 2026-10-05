package admin

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
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
	Passkeys          int      `json:"passkeys"`
	Blocked           bool     `json:"blocked"`
	Admin             bool     `json:"admin"`

	// the state of the account
	Disabled               bool       `json:"disabled"`
	DisabledReason         string     `json:"disabled_reason,omitempty"`
	DisabledAt             *time.Time `json:"disabled_at,omitempty"`
	DisabledBy             string     `json:"disabled_by,omitempty"`
	Locked                 bool       `json:"locked"`
	LockedUntil            *time.Time `json:"locked_until,omitempty"`
	LockReason             string     `json:"lock_reason,omitempty"`
	LockedBy               string     `json:"locked_by,omitempty"`
	PasswordChangeRequired bool       `json:"password_change_required"`

	// LastLoginAt is the last successful login (web, passkey, LDAP…)
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
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

type passkeyDTO struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
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
	passkeys := 0
	if h.passkeysOn {
		list, _ := h.passkeys.ListPasskeys(data.Subject)
		passkeys = len(list)
	}
	user := domain.NewUser(data)
	state, _ := h.states.GetUserState(data.Subject)
	dto := userDTO{
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
		Passkeys:          passkeys,
		Blocked:           h.userBlocked.IsBlocked(loginBlockKey(data.PreferredUsername), h.now()),
		Admin:             user.InGroup(h.adminGroup),

		Disabled:               state.Disabled,
		DisabledReason:         state.DisabledReason,
		DisabledAt:             timePtr(state.DisabledAt),
		DisabledBy:             state.DisabledBy,
		Locked:                 state.IsLocked(h.now()),
		PasswordChangeRequired: state.PasswordChangeRequired,
	}
	if last, ok, _ := h.eventStore.LastEvent(data.Subject, "login.", domain.ResultSuccess); ok {
		dto.LastLoginAt = &last.Time
	}
	if dto.Locked {
		dto.LockedUntil = timePtr(state.LockedUntil)
		dto.LockReason = state.LockReason
		dto.LockedBy = state.LockedBy
	}

	return dto
}

// writableUsers returns false (and writes the error) when the users cannot be changed
func (h *Handler) writableUsers(w http.ResponseWriter) bool {
	if h.users == nil {
		writeError(w, http.StatusMethodNotAllowed, "the users are read only: they are managed in the configuration or in LDAP")
		return false
	}

	return true
}

// userPage is a page of the users of a search
type userPage struct {
	Users []userDTO `json:"users"`
	// Total is the number of users of the search (all the pages)
	Total int `json:"total"`
}

const (
	defaultUserPage = 50
	maxUserPage     = 500
)

// listUsers searches the users: q (username, name, email or group), status
// (admin, disabled, locked, blocked, mfa, no_mfa, passkeys, temporary_password),
// limit and offset. The users are filtered before building their DTOs, that
// read their MFA, passkeys, state and last login.
func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	if h.lister == nil {
		// LDAP cannot list its users
		writeJSON(w, http.StatusOK, userPage{Users: []userDTO{}})
		return
	}

	query := r.URL.Query()
	limit, offset := defaultUserPage, 0
	for name, target := range map[string]*int{"limit": &limit, "offset": &offset} {
		if value := query.Get(name); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 {
				writeError(w, http.StatusBadRequest, "invalid "+name)
				return
			}
			*target = n
		}
	}
	limit = min(max(limit, 1), maxUserPage)

	matches, err := h.userFilter(query.Get("q"), query.Get("status"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	users, err := h.lister.ListUsers()
	if err != nil {
		writeInternalError(w, err)
		return
	}

	page := userPage{Users: []userDTO{}}
	for _, u := range users {
		if !matches(u) {
			continue
		}

		if page.Total >= offset && len(page.Users) < limit {
			page.Users = append(page.Users, h.userDTO(u))
		}
		page.Total++
	}

	writeJSON(w, http.StatusOK, page)
}

// userFilter returns the filter of the search of users
func (h *Handler) userFilter(text, status string) (func(domain.UserData) bool, error) {
	text = strings.ToLower(strings.TrimSpace(text))
	matchesText := func(u domain.UserData) bool {
		if text == "" {
			return true
		}
		for _, value := range append([]string{u.PreferredUsername, u.Name, u.Email}, u.Groups...) {
			if strings.Contains(strings.ToLower(value), text) {
				return true
			}
		}
		return false
	}

	now := h.now()
	state := func(u domain.UserData) domain.UserState {
		s, _ := h.states.GetUserState(u.Subject)
		return s
	}
	hasMFA := func(u domain.UserData) bool {
		ok, _ := h.mfaStore.UserHasMFACodes(u.Subject)
		return ok
	}

	var matchesStatus func(domain.UserData) bool
	switch status {
	case "":
		matchesStatus = func(domain.UserData) bool { return true }
	case "admin":
		matchesStatus = func(u domain.UserData) bool { return domain.NewUser(u).InGroup(h.adminGroup) }
	case "disabled":
		matchesStatus = func(u domain.UserData) bool { return state(u).Disabled }
	case "locked":
		matchesStatus = func(u domain.UserData) bool { return state(u).IsLocked(now) }
	case "blocked":
		matchesStatus = func(u domain.UserData) bool { return h.userBlocked.IsBlocked(loginBlockKey(u.PreferredUsername), now) }
	case "mfa":
		matchesStatus = hasMFA
	case "no_mfa":
		matchesStatus = func(u domain.UserData) bool { return !hasMFA(u) }
	case "passkeys":
		matchesStatus = func(u domain.UserData) bool {
			list, _ := h.passkeys.ListPasskeys(u.Subject)
			return len(list) > 0
		}
	case "temporary_password":
		matchesStatus = func(u domain.UserData) bool { return state(u).PasswordChangeRequired }
	default:
		return nil, fmt.Errorf("unknown status %q", status)
	}

	return func(u domain.UserData) bool { return matchesText(u) && matchesStatus(u) }, nil
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

	h.audit(r, domain.EventAdminUser, domain.NewUser(data), "", "created")
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
	if input.Password != "" && !h.requireRecentLogin(w, r) {
		return
	}
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

	h.audit(r, domain.EventAdminUser, domain.NewUser(data), "", updateDetail(input.Password != ""))
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

	groups := cleanGroups(input.Groups)
	for _, g := range groups {
		if err := validateGroupName(g); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return domain.UserData{}, false
		}
	}

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

	if !h.requireRecentLogin(w, r) {
		return
	}

	h.sessionStore.DeleteUserSessions(user.ID())
	h.mfaStore.DeleteUserMFACodes(user.ID())
	_ = h.resets.DeleteUserPasswordResets(user.ID())
	_ = h.states.DeleteUserState(user.ID())
	if err := h.passkeys.DeleteUserPasskeys(user.ID()); err != nil {
		writeInternalError(w, err)
		return
	}
	if err := h.users.DeleteUser(user.ID()); err != nil {
		writeStoreError(w, err)
		return
	}

	h.audit(r, domain.EventAdminUser, user, "", "deleted")
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
	h.audit(r, domain.EventAdminCredentials, user, "", "all the sessions closed")
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

			h.audit(r, domain.EventAdminCredentials, user, "", "a session closed")
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
	h.audit(r, domain.EventAdminCredentials, user, "", "MFA reset")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listPasskeys(w http.ResponseWriter, r *http.Request) {
	user, ok := h.findUser(w, r)
	if !ok || !h.passkeysEnabled(w) {
		return
	}

	passkeys, err := h.passkeys.ListPasskeys(user.ID())
	if err != nil {
		writeInternalError(w, err)
		return
	}

	result := make([]passkeyDTO, 0, len(passkeys))
	for _, p := range passkeys {
		dto := passkeyDTO{ID: p.ID, Name: p.Name, CreatedAt: p.CreatedAt}
		if !p.LastUsedAt.IsZero() {
			lastUsed := p.LastUsedAt
			dto.LastUsedAt = &lastUsed
		}
		result = append(result, dto)
	}

	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) deletePasskey(w http.ResponseWriter, r *http.Request) {
	user, ok := h.findUser(w, r)
	if !ok || !h.passkeysEnabled(w) {
		return
	}

	if err := h.passkeys.DeletePasskey(user.ID(), r.PathValue("passkey")); err != nil {
		writeError(w, http.StatusNotFound, "passkey not found")
		return
	}

	h.audit(r, domain.EventAdminCredentials, user, "", "a passkey removed")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) deletePasskeys(w http.ResponseWriter, r *http.Request) {
	user, ok := h.findUser(w, r)
	if !ok || !h.passkeysEnabled(w) {
		return
	}

	if err := h.passkeys.DeleteUserPasskeys(user.ID()); err != nil {
		writeInternalError(w, err)
		return
	}

	h.audit(r, domain.EventAdminCredentials, user, "", "all the passkeys removed")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) passkeysEnabled(w http.ResponseWriter) bool {
	if !h.passkeysOn {
		writeError(w, http.StatusNotFound, "the passkeys are disabled")
		return false
	}

	return true
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

package admin

import (
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

const (
	// recentLoginAge is how recent the login of the administrator must be to
	// change the credentials or the state of an account
	recentLoginAge = 10 * time.Minute
	// resetLinkTTL is the lifetime of the password reset links
	resetLinkTTL = 24 * time.Hour
	// temporaryPasswordBytes are the random bytes of a temporary password (16 base32 characters)
	temporaryPasswordBytes = 10
	maxReasonLength        = 256
)

type reasonInput struct {
	Reason string `json:"reason"`
}

type lockInput struct {
	// Until is the end of the lock (RFC 3339). Empty: until it is unlocked.
	Until  string `json:"until"`
	Reason string `json:"reason"`
}

type passwordInput struct {
	Password      string `json:"password"`
	RequireChange bool   `json:"require_change"`
}

// requireRecentLogin checks that the administrator signed in recently: a
// stolen admin session cannot take over the accounts. The error tells the web
// to ask for a new login.
func (h *Handler) requireRecentLogin(w http.ResponseWriter, r *http.Request) bool {
	session := adminSessionFromContext(r)
	if session != nil && !session.AuthTime().IsZero() && h.now().Sub(session.AuthTime()) <= recentLoginAge {
		return true
	}

	writeJSON(w, http.StatusForbidden, map[string]interface{}{
		"error":          "for your security, sign in again to do this",
		"reauthenticate": true,
	})
	return false
}

// accountTarget returns the user of the request for the actions that an
// administrator cannot do to themselves (lock, disable)
func (h *Handler) accountTarget(w http.ResponseWriter, r *http.Request) (domain.User, bool) {
	user, ok := h.findUser(w, r)
	if !ok {
		return nil, false
	}

	if user.ID() == adminFromContext(r).ID() {
		writeError(w, http.StatusBadRequest, "you cannot do this to your own account")
		return nil, false
	}

	return user, h.requireRecentLogin(w, r)
}

func (h *Handler) saveState(w http.ResponseWriter, state domain.UserState) bool {
	if err := h.states.SaveUserState(state); err != nil {
		writeInternalError(w, err)
		return false
	}

	return true
}

func (h *Handler) disableUser(w http.ResponseWriter, r *http.Request) {
	user, ok := h.accountTarget(w, r)
	if !ok {
		return
	}

	var input reasonInput
	if !readJSON(w, r, &input) {
		return
	}

	state, err := h.states.GetUserState(user.ID())
	if err != nil {
		writeInternalError(w, err)
		return
	}

	state.Disabled = true
	state.DisabledReason = clip(input.Reason)
	state.DisabledAt = h.now()
	state.DisabledBy = adminFromContext(r).Data().PreferredUsername
	if !h.saveState(w, state) {
		return
	}

	// the refresh tokens need their session, and the access tokens are
	// rejected when their session does not exist
	h.sessionStore.DeleteUserSessions(user.ID())
	log.Printf("admin: %s has disabled %s", state.DisabledBy, user.Data().PreferredUsername)
	h.audit(r, domain.EventAdminState, user, "", withReason("disabled", state.DisabledReason))
	writeJSON(w, http.StatusOK, h.userDTO(user.Data()))
}

func (h *Handler) enableUser(w http.ResponseWriter, r *http.Request) {
	user, ok := h.findUser(w, r)
	if !ok {
		return
	}

	state, err := h.states.GetUserState(user.ID())
	if err != nil {
		writeInternalError(w, err)
		return
	}

	state.Disabled, state.DisabledReason, state.DisabledAt, state.DisabledBy = false, "", time.Time{}, ""
	if !h.saveState(w, state) {
		return
	}

	log.Printf("admin: %s has enabled %s", adminFromContext(r).Data().PreferredUsername, user.Data().PreferredUsername)
	h.audit(r, domain.EventAdminState, user, "", "enabled")
	writeJSON(w, http.StatusOK, h.userDTO(user.Data()))
}

func (h *Handler) lockUser(w http.ResponseWriter, r *http.Request) {
	user, ok := h.accountTarget(w, r)
	if !ok {
		return
	}

	var input lockInput
	if !readJSON(w, r, &input) {
		return
	}

	now := h.now()
	var until time.Time
	if input.Until != "" {
		var err error
		if until, err = time.Parse(time.RFC3339, input.Until); err != nil || !until.After(now) {
			writeError(w, http.StatusBadRequest, "the end of the lock must be a future date")
			return
		}
	}

	state, err := h.states.GetUserState(user.ID())
	if err != nil {
		writeInternalError(w, err)
		return
	}

	state.Locked = true
	state.LockedUntil = until
	state.LockReason = clip(input.Reason)
	state.LockedAt = now
	state.LockedBy = adminFromContext(r).Data().PreferredUsername
	if !h.saveState(w, state) {
		return
	}

	h.sessionStore.DeleteUserSessions(user.ID())
	log.Printf("admin: %s has locked %s", state.LockedBy, user.Data().PreferredUsername)
	h.audit(r, domain.EventAdminState, user, "", withReason(lockDetail(until), state.LockReason))
	writeJSON(w, http.StatusOK, h.userDTO(user.Data()))
}

// unblockUser removes the lock of the administrators and the automatic one
// of the failed attempts
func (h *Handler) unblockUser(w http.ResponseWriter, r *http.Request) {
	user, ok := h.findUser(w, r)
	if !ok {
		return
	}

	h.userBlocked.Reset(loginBlockKey(user.Data().PreferredUsername))
	h.userBlocked.Reset(mfaBlockKey(user.ID()))

	state, err := h.states.GetUserState(user.ID())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if state.Locked {
		state.Locked, state.LockedUntil, state.LockReason, state.LockedAt, state.LockedBy = false, time.Time{}, "", time.Time{}, ""
		if !h.saveState(w, state) {
			return
		}
	}

	h.audit(r, domain.EventAdminState, user, "", "unlocked")
	w.WriteHeader(http.StatusNoContent)
}

// passwordUpdater is nil when the passwords cannot be changed (LDAP, the users of the configuration)
func (h *Handler) passwordUpdater() domain.PasswordUpdater {
	if h.users == nil {
		return nil
	}

	updater, _ := h.users.(domain.PasswordUpdater)
	return updater
}

// passwordTarget returns the user whose password is changed
func (h *Handler) passwordTarget(w http.ResponseWriter, r *http.Request) (domain.User, domain.PasswordUpdater, bool) {
	updater := h.passwordUpdater()
	if updater == nil {
		writeError(w, http.StatusMethodNotAllowed, "the passwords of these users cannot be changed here")
		return nil, nil, false
	}

	user, ok := h.findUser(w, r)
	if !ok || !h.requireRecentLogin(w, r) {
		return nil, nil, false
	}

	return user, updater, true
}

// changePassword stores the password and closes the sessions of the user: the
// administrator changes it when it is lost or stolen
func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request, user domain.User, updater domain.PasswordUpdater, password string, requireChange bool) bool {
	hash, err := cryptography.HashPassword(password)
	if err == nil {
		err = updater.UpdatePassword(user.ID(), hash)
	}
	if err != nil {
		writeInternalError(w, err)
		return false
	}

	state, err := h.states.GetUserState(user.ID())
	if err != nil {
		writeInternalError(w, err)
		return false
	}

	state.PasswordChangeRequired = requireChange
	if !h.saveState(w, state) {
		return false
	}

	_ = h.resets.DeleteUserPasswordResets(user.ID())
	h.userBlocked.Reset(loginBlockKey(user.Data().PreferredUsername))
	if user.ID() != adminFromContext(r).ID() {
		h.sessionStore.DeleteUserSessions(user.ID())
	}

	log.Printf("admin: %s has changed the password of %s", adminFromContext(r).Data().PreferredUsername, user.Data().PreferredUsername)
	return true
}

func (h *Handler) setPassword(w http.ResponseWriter, r *http.Request) {
	user, updater, ok := h.passwordTarget(w, r)
	if !ok {
		return
	}

	var input passwordInput
	if !readJSON(w, r, &input) {
		return
	}

	if len(input.Password) < minPasswordLength {
		writeError(w, http.StatusBadRequest, "the password must have at least 8 characters")
		return
	}

	if h.changePassword(w, r, user, updater, input.Password, input.RequireChange) {
		h.audit(r, domain.EventAdminPassword, user, "", requireChangeDetail("password set", input.RequireChange))
		writeJSON(w, http.StatusOK, h.userDTO(mustData(h, user)))
	}
}

// temporaryPassword sets a random password that the user must change in the
// next login. It is shown once.
func (h *Handler) temporaryPassword(w http.ResponseWriter, r *http.Request) {
	user, updater, ok := h.passwordTarget(w, r)
	if !ok {
		return
	}

	password, err := cryptography.RandomPassword(temporaryPasswordBytes)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	password = groupsOf4(password)

	if h.changePassword(w, r, user, updater, password, true) {
		h.audit(r, domain.EventAdminPassword, user, "", "temporary password")
		writeJSON(w, http.StatusOK, map[string]string{"password": password})
	}
}

// resetLink creates a single use link to choose a new password. The previous
// links of the user stop working.
func (h *Handler) resetLink(w http.ResponseWriter, r *http.Request) {
	user, _, ok := h.passwordTarget(w, r)
	if !ok {
		return
	}

	token, err := cryptography.RandomToken()
	if err != nil {
		writeInternalError(w, err)
		return
	}

	expiresAt := h.now().Add(resetLinkTTL)
	if err := h.resets.NewPasswordReset(cryptography.SHA256(token), user.ID(), expiresAt); err != nil {
		writeInternalError(w, err)
		return
	}

	log.Printf("admin: %s has created a password reset link for %s", adminFromContext(r).Data().PreferredUsername, user.Data().PreferredUsername)
	h.audit(r, domain.EventAdminPassword, user, "", "reset link created")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"url":        h.resetURL + "?" + url.Values{"token": {token}}.Encode(),
		"expires_at": expiresAt,
	})
}

// mustData reads the user again (the password has changed)
func mustData(h *Handler, user domain.User) domain.UserData {
	if updated, err := h.userStore.GetUserByID(user.ID()); err == nil {
		return updated.Data()
	}

	return user.Data()
}

// groupsOf4 makes the temporary passwords easy to read and type: ABCD-EFGH-…
func groupsOf4(value string) string {
	var b strings.Builder
	for i, c := range value {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(c)
	}

	return b.String()
}

func clip(reason string) string {
	reason = strings.TrimSpace(reason)
	if runes := []rune(reason); len(runes) > maxReasonLength {
		return string(runes[:maxReasonLength])
	}

	return reason
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}

	return &t
}

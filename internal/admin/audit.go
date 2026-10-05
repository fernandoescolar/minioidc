package admin

import (
	"net/http"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// audit writes an action of the administrator in the activity log. user is
// the account of the action (nil for the clients and the maintenance).
func (h *Handler) audit(r *http.Request, eventType string, user domain.User, clientID, detail string) {
	event := domain.Event{Type: eventType, Result: domain.ResultSuccess, ClientID: clientID, Detail: detail}
	if admin := adminFromContext(r); admin != nil {
		event.Actor = admin.Data().PreferredUsername
	}
	if user != nil {
		event.UserID = user.ID()
		event.Username = user.Data().PreferredUsername
	}

	h.events.Record(r, event)
}

func updateDetail(passwordChanged bool) string {
	if passwordChanged {
		return "updated, with a new password"
	}

	return "updated"
}

func withReason(detail, reason string) string {
	if reason == "" {
		return detail
	}

	return detail + ": " + reason
}

func lockDetail(until time.Time) string {
	if until.IsZero() {
		return "locked until it is unlocked"
	}

	return "locked until " + until.UTC().Format(time.RFC3339)
}

func requireChangeDetail(detail string, requireChange bool) string {
	if requireChange {
		return detail + " (must be changed)"
	}

	return detail
}

package admin

import (
	"net/http"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// maxIncidents is the number of recent failures of the overview
const maxIncidents = 8

type userCounts struct {
	Total             int `json:"total"`
	Admins            int `json:"admins"`
	Disabled          int `json:"disabled"`
	Locked            int `json:"locked"`
	Blocked           int `json:"blocked"`
	WithMFA           int `json:"with_mfa"`
	WithPasskeys      int `json:"with_passkeys"`
	TemporaryPassword int `json:"temporary_password"`
	NeverSignedIn     int `json:"never_signed_in"`
}

type overview struct {
	// Users is nil when the users cannot be listed (LDAP)
	Users     *userCounts    `json:"users"`
	Clients   int            `json:"clients"`
	Groups    int            `json:"groups"`
	Activity  map[string]int `json:"activity"`
	Incidents []eventDTO     `json:"incidents"`
}

// overview is the dashboard of the admin web: the state of the accounts, the
// activity of the last 24 hours and the last incidents
func (h *Handler) overview(w http.ResponseWriter, _ *http.Request) {
	result := overview{Incidents: []eventDTO{}}
	now := h.now()

	if h.lister != nil {
		users, err := h.lister.ListUsers()
		if err != nil {
			writeInternalError(w, err)
			return
		}

		counts := &userCounts{Total: len(users)}
		for _, u := range users {
			state, _ := h.states.GetUserState(u.Subject)
			hasMFA, _ := h.mfaStore.UserHasMFACodes(u.Subject)
			passkeys, _ := h.passkeys.ListPasskeys(u.Subject)
			_, signedIn, _ := h.eventStore.LastEvent(u.Subject, "login.", domain.ResultSuccess)
			count(&counts.Admins, domain.NewUser(u).InGroup(h.adminGroup))
			count(&counts.Disabled, state.Disabled)
			count(&counts.Locked, state.IsLocked(now))
			count(&counts.Blocked, h.userBlocked.IsBlocked(loginBlockKey(u.PreferredUsername), now))
			count(&counts.WithMFA, hasMFA)
			count(&counts.WithPasskeys, len(passkeys) > 0)
			count(&counts.TemporaryPassword, state.PasswordChangeRequired)
			count(&counts.NeverSignedIn, !signedIn)
		}
		result.Users = counts
	}

	clients, err := h.clients.ListClients()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	result.Clients = len(clients)

	groups := map[string]bool{}
	if definitions, err := h.groupStore.ListGroups(); err == nil {
		for _, g := range definitions {
			groups[strings.ToLower(g.Name)] = true
		}
	}
	if users, err := h.allUsers(); err == nil {
		for _, u := range users {
			for _, g := range u.Groups {
				groups[strings.ToLower(g)] = true
			}
		}
	}
	result.Groups = len(groups)

	activity, err := h.activitySummary(now.Add(-24 * time.Hour))
	if err != nil {
		writeInternalError(w, err)
		return
	}
	result.Activity = activity

	incidents, err := h.eventStore.ListEvents(domain.EventFilter{Result: domain.ResultFailure, Limit: maxIncidents})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	for _, e := range incidents {
		result.Incidents = append(result.Incidents, eventToDTO(e))
	}

	writeJSON(w, http.StatusOK, result)
}

func count(counter *int, condition bool) {
	if condition {
		*counter++
	}
}

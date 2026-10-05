package admin

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

const (
	defaultEventPage = 50
	maxEventPage     = 200
	// maxEventExport is the maximum number of events of a CSV export
	maxEventExport = 10000
)

type eventDTO struct {
	ID        int64     `json:"id"`
	Time      time.Time `json:"time"`
	Type      string    `json:"type"`
	Result    string    `json:"result"`
	UserID    string    `json:"user_id,omitempty"`
	Username  string    `json:"username,omitempty"`
	ClientID  string    `json:"client_id,omitempty"`
	Actor     string    `json:"actor,omitempty"`
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	Detail    string    `json:"detail,omitempty"`
}

type eventPage struct {
	Events []eventDTO `json:"events"`
	// Next is the "before" of the next page (0: there are no more events)
	Next int64 `json:"next"`
}

// eventFilter reads the filter of the query: user (subject), q, type
// (prefix), result, since and until (RFC 3339), before and limit
func (h *Handler) eventFilter(w http.ResponseWriter, r *http.Request, maxLimit int) (domain.EventFilter, bool) {
	query := r.URL.Query()
	filter := domain.EventFilter{
		UserID:     query.Get("user"),
		Search:     query.Get("q"),
		TypePrefix: query.Get("type"),
		Result:     query.Get("result"),
		Limit:      maxLimit,
	}

	// the failed logins of unknown subjects have the username
	if filter.UserID != "" {
		if user, err := h.userStore.GetUserByID(filter.UserID); err == nil {
			filter.Username = user.Data().PreferredUsername
		}
	}

	for name, target := range map[string]*time.Time{"since": &filter.Since, "until": &filter.Until} {
		if value := query.Get(name); value != "" {
			t, err := time.Parse(time.RFC3339, value)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid "+name+": use RFC 3339")
				return filter, false
			}
			*target = t
		}
	}

	if value := query.Get("before"); value != "" {
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "invalid before")
			return filter, false
		}
		filter.Before = n
	}

	if value := query.Get("limit"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n <= 0 {
			writeError(w, http.StatusBadRequest, "invalid limit")
			return filter, false
		}
		filter.Limit = min(n, maxLimit)
	} else if maxLimit == maxEventPage {
		filter.Limit = defaultEventPage
	}

	return filter, true
}

func (h *Handler) listEvents(w http.ResponseWriter, r *http.Request) {
	filter, ok := h.eventFilter(w, r, maxEventPage)
	if !ok {
		return
	}

	// one more to know if there is a next page
	limit := filter.Limit
	filter.Limit++
	events, err := h.eventStore.ListEvents(filter)
	if err != nil {
		writeInternalError(w, err)
		return
	}

	page := eventPage{Events: make([]eventDTO, 0, len(events))}
	if len(events) > limit {
		events = events[:limit]
		page.Next = events[len(events)-1].ID
	}
	for _, e := range events {
		page.Events = append(page.Events, eventToDTO(e))
	}

	writeJSON(w, http.StatusOK, page)
}

func (h *Handler) exportEvents(w http.ResponseWriter, r *http.Request) {
	filter, ok := h.eventFilter(w, r, maxEventExport)
	if !ok {
		return
	}

	events, err := h.eventStore.ListEvents(filter)
	if err != nil {
		writeInternalError(w, err)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="minioidc-activity.csv"`)
	out := csv.NewWriter(w)
	_ = out.Write([]string{"time", "type", "result", "user_id", "username", "client_id", "actor", "ip", "user_agent", "detail"})
	for _, e := range events {
		_ = out.Write([]string{
			e.Time.UTC().Format(time.RFC3339), e.Type, e.Result, e.UserID, csvSafe(e.Username), csvSafe(e.ClientID),
			csvSafe(e.Actor), e.IP, csvSafe(e.UserAgent), csvSafe(e.Detail),
		})
	}
	out.Flush()
}

// csvSafe avoids the formula injection in the spreadsheets: the values that
// start with =, +, - or @ are prefixed with a quote
func csvSafe(value string) string {
	if value != "" && (value[0] == '=' || value[0] == '+' || value[0] == '-' || value[0] == '@' || value[0] == '\t' || value[0] == '\r') {
		return "'" + value
	}

	return value
}

// eventSummary counts the events of the last 24 hours: the incidents at a glance
func (h *Handler) eventSummary(w http.ResponseWriter, _ *http.Request) {
	counts, err := h.activitySummary(h.now().Add(-24 * time.Hour))
	if err != nil {
		writeInternalError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, counts)
}

// activitySummary counts the sign ins, failures, blocks, account changes and
// admin actions since a time
func (h *Handler) activitySummary(since time.Time) (map[string]int, error) {
	counts := map[string]int{}
	for name, filter := range map[string]domain.EventFilter{
		"logins":          {TypePrefix: "login.", Result: domain.ResultSuccess, Since: since},
		"failed_logins":   {TypePrefix: "login.", Result: domain.ResultFailure, Since: since},
		"lockouts":        {TypePrefix: domain.EventLoginLockout, Since: since},
		"admin_actions":   {TypePrefix: "admin.", Since: since},
		"account_changes": {TypePrefix: "account.", Result: domain.ResultSuccess, Since: since},
	} {
		count, err := h.eventStore.CountEvents(filter)
		if err != nil {
			return nil, err
		}
		counts[name] = count
	}

	return counts, nil
}

func eventToDTO(e domain.Event) eventDTO {
	return eventDTO{
		ID: e.ID, Time: e.Time, Type: e.Type, Result: e.Result, UserID: e.UserID, Username: e.Username,
		ClientID: e.ClientID, Actor: e.Actor, IP: e.IP, UserAgent: e.UserAgent, Detail: e.Detail,
	}
}

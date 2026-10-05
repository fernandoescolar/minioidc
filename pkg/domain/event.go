package domain

import (
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// The types of the events. The prefix groups them: login., account., admin.
const (
	EventLoginPassword      = "login.password"
	EventLoginPasskey       = "login.passkey"
	EventLoginMFA           = "login.mfa"
	EventLoginLockout       = "login.lockout"
	EventLoginLDAP          = "login.ldap"
	EventLoginPasswordGrant = "login.password_grant"
	// EventLoginDenied is a user that is not in the allowed groups of a client
	EventLoginDenied = "login.denied"
	EventLogout      = "logout"

	EventPasswordChange = "account.password_change"
	EventPasswordReset  = "account.password_reset"
	EventMFAAdd         = "account.mfa_add"
	EventMFARemove      = "account.mfa_remove"
	EventPasskeyAdd     = "account.passkey_add"
	EventPasskeyRemove  = "account.passkey_remove"
	EventDeviceApprove  = "account.device_approve"
	EventSetup          = "account.setup"

	EventAdminUser        = "admin.user"
	EventAdminPassword    = "admin.password"
	EventAdminState       = "admin.state"
	EventAdminCredentials = "admin.credentials"
	EventAdminClient      = "admin.client"
	EventAdminMaintenance = "admin.maintenance"
	EventAdminGroup       = "admin.group"
	EventAdminSettings    = "admin.settings"
)

const (
	ResultSuccess = "success"
	ResultFailure = "failure"
)

// Event is an entry of the activity log
type Event struct {
	ID     int64
	Time   time.Time
	Type   string
	Result string
	// UserID and Username are the user of the event (the subject can be empty
	// in the failed logins of unknown users)
	UserID   string
	Username string
	ClientID string
	// Actor is the administrator of the admin events
	Actor     string
	IP        string
	UserAgent string
	// Detail describes the event (e.g. "invalid credentials", "disabled")
	Detail string
}

// EventFilter selects the events. The zero values do not filter.
type EventFilter struct {
	UserID string
	// Username adds, to the events of UserID, the events without subject of
	// this username (e.g. the failed logins, where the user is not known)
	Username string
	// Search looks for the text in the username, the actor, the client and the IP
	Search string
	// TypePrefix selects the types that start with it (e.g. "login.")
	TypePrefix string
	Result     string
	Since      time.Time
	Until      time.Time
	// Before returns the events older than this ID (pagination)
	Before int64
	Limit  int
}

// Matches is the filter of the stores that do not use SQL
func (f EventFilter) Matches(e Event) bool {
	return (f.UserID == "" || e.UserID == f.UserID || (f.Username != "" && e.UserID == "" && strings.EqualFold(e.Username, f.Username))) &&
		strings.HasPrefix(e.Type, f.TypePrefix) &&
		(f.Result == "" || e.Result == f.Result) &&
		(f.Since.IsZero() || !e.Time.Before(f.Since)) &&
		(f.Until.IsZero() || e.Time.Before(f.Until)) &&
		(f.Before == 0 || e.ID < f.Before) &&
		(f.Search == "" || containsFold(e.Username, f.Search) || containsFold(e.Actor, f.Search) ||
			containsFold(e.ClientID, f.Search) || containsFold(e.IP, f.Search))
}

type EventStore interface {
	AddEvent(event Event) error
	// ListEvents returns the events of the filter, the newest first
	ListEvents(filter EventFilter) ([]Event, error)
	// CountEvents returns the number of events of the filter (without its limit)
	CountEvents(filter EventFilter) (int, error)
	// LastEvent returns the newest event of the user with the type and result
	LastEvent(userID, eventType, result string) (Event, bool, error)
	// DeleteEventsBefore removes the old events (the retention)
	DeleteEventsBefore(t time.Time) error
}

// Recorder writes the events of the requests: it adds the time, the IP and
// the user agent. The errors are logged: the activity log does not stop the
// requests.
type Recorder struct {
	Store EventStore
	Now   func() time.Time
}

// Record writes the event. r can be nil (e.g. the LDAP binds).
func (rec *Recorder) Record(r *http.Request, event Event) {
	if rec == nil || rec.Store == nil {
		return
	}

	event.Time = rec.Now()
	if r != nil {
		event.IP = clientIP(r)
		event.UserAgent = truncate(r.UserAgent(), 256)
	}
	event.Username = truncate(event.Username, 128)
	event.Detail = truncate(event.Detail, 512)

	if err := rec.Store.AddEvent(event); err != nil {
		log.Printf("WRN activity log: %v", err)
	}
}

// RecordUser writes an event of a user
func (rec *Recorder) RecordUser(r *http.Request, eventType, result string, user User, detail string) {
	event := Event{Type: eventType, Result: result, Detail: detail}
	if user != nil {
		event.UserID = user.ID()
		event.Username = user.Data().PreferredUsername
	}
	rec.Record(r, event)
}

// clientIP is the address of the client, without the port (the
// ForwardedHeaders middleware sets it behind a proxy)
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}

	return r.RemoteAddr
}

func truncate(value string, max int) string {
	if runes := []rune(value); len(runes) > max {
		return string(runes[:max])
	}

	return value
}

func containsFold(value, text string) bool {
	return strings.Contains(strings.ToLower(value), strings.ToLower(text))
}

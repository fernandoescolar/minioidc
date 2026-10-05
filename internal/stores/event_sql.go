package stores

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

const eventColumns = "id, time, type, result, userID, username, clientID, actor, ip, userAgent, detail"

type sqlEventStore struct {
	db *sql.DB
}

// NewSqliteEventStore initializes an EventStore in SQLite. The times are
// stored as unix milliseconds.
func NewSqliteEventStore(db *sql.DB) domain.EventStore {
	return &sqlEventStore{db: db}
}

func (s *sqlEventStore) AddEvent(e domain.Event) error {
	_, err := s.db.Exec("INSERT INTO events(time, type, result, userID, username, clientID, actor, ip, userAgent, detail) VALUES(?,?,?,?,?,?,?,?,?,?);",
		e.Time.UnixMilli(), e.Type, e.Result, e.UserID, e.Username, e.ClientID, e.Actor, e.IP, e.UserAgent, e.Detail)
	if err != nil {
		return fmt.Errorf("AddEvent: %w", err)
	}

	return nil
}

func (s *sqlEventStore) ListEvents(f domain.EventFilter) ([]domain.Event, error) {
	where, args := eventWhere(f)
	query := "SELECT " + eventColumns + " FROM events" + where + " ORDER BY id DESC"
	if f.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, f.Limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("ListEvents: %w", err)
	}
	defer rows.Close()

	events := []domain.Event{}
	for rows.Next() {
		var (
			e  domain.Event
			ms int64
		)
		if err := rows.Scan(&e.ID, &ms, &e.Type, &e.Result, &e.UserID, &e.Username, &e.ClientID, &e.Actor, &e.IP, &e.UserAgent, &e.Detail); err != nil {
			return nil, fmt.Errorf("ListEvents: %w", err)
		}
		e.Time = time.UnixMilli(ms)
		events = append(events, e)
	}

	return events, rows.Err()
}

func (s *sqlEventStore) CountEvents(f domain.EventFilter) (int, error) {
	where, args := eventWhere(f)
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM events"+where, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("CountEvents: %w", err)
	}

	return count, nil
}

// eventWhere is the WHERE clause of the filter (without its limit)
func eventWhere(f domain.EventFilter) (string, []interface{}) {
	var (
		where []string
		args  []interface{}
	)
	add := func(condition string, values ...interface{}) {
		where = append(where, condition)
		args = append(args, values...)
	}

	switch {
	case f.UserID != "" && f.Username != "":
		add("(userID = ? OR (userID = '' AND username = ? COLLATE NOCASE))", f.UserID, f.Username)
	case f.UserID != "":
		add("userID = ?", f.UserID)
	}
	if f.TypePrefix != "" {
		// the types are constants without wildcards; the prefix is escaped anyway
		add("type LIKE ? ESCAPE '\\'", escapeLike(f.TypePrefix)+"%")
	}
	if f.Result != "" {
		add("result = ?", f.Result)
	}
	if !f.Since.IsZero() {
		add("time >= ?", f.Since.UnixMilli())
	}
	if !f.Until.IsZero() {
		add("time < ?", f.Until.UnixMilli())
	}
	if f.Before > 0 {
		add("id < ?", f.Before)
	}
	if f.Search != "" {
		pattern := "%" + escapeLike(f.Search) + "%"
		add("(username LIKE ? ESCAPE '\\' OR actor LIKE ? ESCAPE '\\' OR clientID LIKE ? ESCAPE '\\' OR ip LIKE ? ESCAPE '\\')", pattern, pattern, pattern, pattern)
	}

	if len(where) == 0 {
		return "", args
	}

	return " WHERE " + strings.Join(where, " AND "), args
}

func (s *sqlEventStore) LastEvent(userID, eventType, result string) (domain.Event, bool, error) {
	events, err := s.ListEvents(domain.EventFilter{UserID: userID, TypePrefix: eventType, Result: result, Limit: 1})
	if err != nil || len(events) == 0 {
		return domain.Event{}, false, err
	}

	return events[0], true, nil
}

func (s *sqlEventStore) DeleteEventsBefore(t time.Time) error {
	_, err := s.db.Exec("DELETE FROM events WHERE time < ?;", t.UnixMilli())
	return err
}

// escapeLike escapes the wildcards of a LIKE pattern
func escapeLike(value string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value)
}

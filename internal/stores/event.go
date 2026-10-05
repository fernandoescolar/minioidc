package stores

import (
	"sync"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// maxMemoryEvents is the size of the activity log in memory: the oldest
// events are removed
const maxMemoryEvents = 10000

type miniEventStore struct {
	mu     sync.RWMutex
	events []domain.Event
	nextID int64
}

// NewEventStore initializes an EventStore in memory with the last events
func NewEventStore() domain.EventStore {
	return &miniEventStore{nextID: 1}
}

func (s *miniEventStore) AddEvent(event domain.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	event.ID = s.nextID
	s.nextID++
	s.events = append(s.events, event)
	if len(s.events) > maxMemoryEvents {
		s.events = append([]domain.Event{}, s.events[len(s.events)-maxMemoryEvents:]...)
	}

	return nil
}

func (s *miniEventStore) ListEvents(filter domain.EventFilter) ([]domain.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	events := []domain.Event{}
	for i := len(s.events) - 1; i >= 0 && (filter.Limit <= 0 || len(events) < filter.Limit); i-- {
		if filter.Matches(s.events[i]) {
			events = append(events, s.events[i])
		}
	}

	return events, nil
}

func (s *miniEventStore) CountEvents(filter domain.EventFilter) (int, error) {
	filter.Limit = 0
	events, err := s.ListEvents(filter)
	return len(events), err
}

func (s *miniEventStore) LastEvent(userID, eventType, result string) (domain.Event, bool, error) {
	events, err := s.ListEvents(domain.EventFilter{UserID: userID, TypePrefix: eventType, Result: result, Limit: 1})
	if err != nil || len(events) == 0 {
		return domain.Event{}, false, err
	}

	return events[0], true, nil
}

func (s *miniEventStore) DeleteEventsBefore(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.events[:0]
	for _, e := range s.events {
		if !e.Time.Before(t) {
			kept = append(kept, e)
		}
	}
	s.events = kept
	return nil
}

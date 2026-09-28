package stores

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type sqlClientAssertionStore struct {
	db *sql.DB
}

// NewSqliteClientAssertionStore initializes a ClientAssertionStore in SQLite.
// The dates are unix timestamps, so they are compared as numbers.
func NewSqliteClientAssertionStore(db *sql.DB) domain.ClientAssertionStore {
	return &sqlClientAssertionStore{db: db}
}

func (s *sqlClientAssertionStore) Use(id string, expiresAt, now time.Time) (bool, error) {
	// a single statement, so two concurrent requests (even from different
	// instances) cannot use the same assertion: only one of them changes a row
	r, err := s.db.Exec(`INSERT INTO client_assertions(id, expiresAt) VALUES(?, ?)
		ON CONFLICT(id) DO UPDATE SET expiresAt = excluded.expiresAt WHERE client_assertions.expiresAt <= ?;`,
		id, expiresAt.Unix(), now.Unix())
	if err != nil {
		return false, fmt.Errorf("Use client assertion: %w", err)
	}

	rows, err := r.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("Use client assertion: %w", err)
	}

	return rows == 1, nil
}

func (s *sqlClientAssertionStore) CleanExpired(now time.Time) {
	if _, err := s.db.Exec("DELETE FROM client_assertions WHERE expiresAt <= ?;", now.Unix()); err != nil {
		log.Printf("WRN Client assertions CleanExpired: %v", err)
	}
}

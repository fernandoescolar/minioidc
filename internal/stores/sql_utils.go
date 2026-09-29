package stores

import (
	"database/sql"
	"fmt"
	"time"
)

// deleteExpired deletes the rows of a table (with id and expiresAt columns)
// that have expired. All the ids are read before deleting them, because
// there is only one SQLite connection.
func deleteExpired(db *sql.DB, table string, now time.Time) error {
	// the table name is a constant of the stores, not user input
	rows, err := db.Query(fmt.Sprintf("SELECT id, expiresAt FROM %s;", table))
	if err != nil {
		return err
	}

	var expired []string
	for rows.Next() {
		var (
			id        string
			expiresAt time.Time
		)
		if err := rows.Scan(&id, &expiresAt); err != nil {
			rows.Close()
			return err
		}

		if !now.Before(expiresAt) {
			expired = append(expired, id)
		}
	}

	if err := rows.Close(); err != nil {
		return err
	}

	for _, id := range expired {
		if _, err := db.Exec(fmt.Sprintf("DELETE FROM %s WHERE id = ?;", table), id); err != nil {
			return err
		}
	}

	return nil
}

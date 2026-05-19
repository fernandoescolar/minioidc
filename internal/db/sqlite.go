package db

import (
	"database/sql"
	"fmt"
	"os"

	// needed for sqlite
	_ "modernc.org/sqlite"
)

const createSqlite string = `
  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
	userID TEXT NOT NULL,
	requireMFA INTEGER DEFAULT 1,
	expiresAt DATETIME NOT NULL,
	authTime DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS grants (
	id TEXT PRIMARY KEY,
	grantType TEXT NOT NULL,
	clientID TEXT NOT NULL,
	sessionID TEXT NOT NULL,
	issuedAt DATETIME NOT NULL,
	expiresAt DATETIME NOT NULL,
	scopes TEXT NOT NULL,
	nonce TEXT,
	codeChallenge TEXT,
	codeChallengeMethod TEXT
  );
  CREATE TABLE IF NOT EXISTS mfa (
	id TEXT PRIMARY KEY,
	userID TEXT NOT NULL,
	secret TEXT NOT NULL,
	method TEXT NOT NULL
  );`

func NewSqliteDB(filepath string) (*sql.DB, error) {
	if _, err := os.Stat(filepath); err != nil {
		_, err := os.Create(filepath)
		if err != nil {
			return nil, fmt.Errorf("NewSqliteDB: %w", err)
		}
	}

	database, err := sql.Open("sqlite", filepath)
	if err != nil {
		return nil, fmt.Errorf("NewSqliteDB: %w", err)
	}

	if _, err := database.Exec(createSqlite); err != nil {
		return nil, fmt.Errorf("NewSqliteDB: %w", err)
	}

	if err := migrateSqlite(database); err != nil {
		return nil, fmt.Errorf("NewSqliteDB: %w", err)
	}

	return database, nil
}

func migrateSqlite(db *sql.DB) error {
	if err := migrateAddColumn(db, "sessions", "authTime", `ALTER TABLE sessions ADD COLUMN authTime DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;`); err != nil {
		return err
	}
	if err := migrateAddColumn(db, "grants", "issuedAt", `ALTER TABLE grants ADD COLUMN issuedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;`); err != nil {
		return err
	}
	return nil
}

func migrateAddColumn(db *sql.DB, table, column, alterSQL string) error {
	rows, err := db.Query("PRAGMA table_info(" + table + ");")
	if err != nil {
		return fmt.Errorf("migrateSqlite: table_info %s: %w", table, err)
	}
	defer rows.Close()

	hasColumn := false
	for rows.Next() {
		var cid, notNull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return fmt.Errorf("migrateSqlite: scan %s: %w", table, err)
		}
		if name == column {
			hasColumn = true
		}
	}

	if !hasColumn {
		if _, err := db.Exec(alterSQL); err != nil {
			return fmt.Errorf("migrateSqlite: add %s.%s: %w", table, column, err)
		}
	}
	return nil
}

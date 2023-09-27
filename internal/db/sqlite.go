package db

import (
	"database/sql"
	"fmt"
	"os"

	// needed for sqlite3
	_ "github.com/mattn/go-sqlite3"
)

const createSqlite string = `
  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
	userID TEXT NOT NULL,
	expiresAt DATETIME NOT NULL
  );
  CREATE TABLE IF NOT EXISTS grants (
	id TEXT PRIMARY KEY,
	grantType TEXT NOT NULL,
	clientID TEXT NOT NULL,
	sessionID TEXT NOT NULL,
	expiresAt DATETIME NOT NULL,
	scopes TEXT NOT NULL,
	nonce TEXT,
	codeChallenge TEXT,
	codeChallengeMethod TEXT
  );`

func NewSqliteDB(filepath string) (*sql.DB, error) {
	if _, err := os.Stat(filepath); err != nil {
		_, err := os.Create(filepath)
		if err != nil {
			return nil, fmt.Errorf("NewSqliteDB: %w", err)
		}
	}

	database, err := sql.Open("sqlite3", filepath)
	if err != nil {
		return nil, fmt.Errorf("NewSqliteDB: %w", err)
	}

	if _, err := database.Exec(createSqlite); err != nil {
		return nil, fmt.Errorf("NewSqliteDB: %w", err)
	}

	return database, nil
}

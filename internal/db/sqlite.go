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

	return database, nil
}

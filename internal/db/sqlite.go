package db

import (
	"database/sql"
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
		os.Create(filepath)
	}

	db, err := sql.Open("sqlite3", filepath)
	if err != nil {
		return nil, err
	}

	if _, err := db.Exec(createSqlite); err != nil {
		return nil, err
	}

	return db, nil
}

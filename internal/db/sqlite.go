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
	authTime DATETIME,
	mfaVerified INTEGER DEFAULT 0
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
	codeChallengeMethod TEXT,
	redirectURI TEXT,
	familyID TEXT,
	used INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS users (
	subject TEXT PRIMARY KEY,
	preferredUsername TEXT NOT NULL UNIQUE,
	email TEXT NOT NULL DEFAULT '',
	emailVerified INTEGER NOT NULL DEFAULT 0,
	name TEXT NOT NULL DEFAULT '',
	givenName TEXT NOT NULL DEFAULT '',
	familyName TEXT NOT NULL DEFAULT '',
	phone TEXT NOT NULL DEFAULT '',
	address TEXT NOT NULL DEFAULT '',
	groups TEXT NOT NULL DEFAULT '[]',
	passwordHash TEXT NOT NULL DEFAULT ''
  );
  CREATE TABLE IF NOT EXISTS clients (
	id TEXT PRIMARY KEY,
	secretHash TEXT NOT NULL DEFAULT '',
	encryptedSecret TEXT NOT NULL DEFAULT '',
	redirectURIs TEXT NOT NULL DEFAULT '[]',
	postLogoutRedirectURIs TEXT NOT NULL DEFAULT '[]',
	authMethod TEXT NOT NULL DEFAULT '',
	jwksURI TEXT NOT NULL DEFAULT '',
	publicKeys TEXT NOT NULL DEFAULT '[]'
  );
  CREATE TABLE IF NOT EXISTS client_assertions (
	id TEXT PRIMARY KEY,
	expiresAt INTEGER NOT NULL
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

	// the pragmas are in the DSN, so they apply to every connection: WAL lets
	// other processes read while there is a writer, and busy_timeout waits for
	// the lock of other processes sharing the file instead of failing with SQLITE_BUSY
	dsn := "file:" + filepath + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("NewSqliteDB: %w", err)
	}

	// SQLite allows only one writer: a single connection serializes the
	// requests of this process instead of making them compete for the lock
	database.SetMaxOpenConns(1)

	if _, err := database.Exec(createSqlite); err != nil {
		return nil, fmt.Errorf("NewSqliteDB: %w", err)
	}

	if err := migrate(database); err != nil {
		return nil, fmt.Errorf("NewSqliteDB: %w", err)
	}

	return database, nil
}

// migrate updates databases created by previous versions
func migrate(database *sql.DB) error {
	if err := addColumn(database, "sessions", "authTime", "DATETIME"); err != nil {
		return err
	}

	if err := addColumn(database, "sessions", "mfaVerified", "INTEGER DEFAULT 0"); err != nil {
		return err
	}

	for column, columnType := range map[string]string{"redirectURI": "TEXT", "familyID": "TEXT", "used": "INTEGER DEFAULT 0"} {
		if err := addColumn(database, "grants", column, columnType); err != nil {
			return err
		}
	}

	_, err := database.Exec("CREATE INDEX IF NOT EXISTS grants_familyID ON grants(familyID);")
	return err
}

// addColumn adds a column to a table if it does not exist
func addColumn(database *sql.DB, table, column, columnType string) error {
	var count int
	row := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?;", table, column)
	if err := row.Scan(&count); err != nil {
		return err
	}

	if count > 0 {
		return nil
	}

	// table, column and columnType are constants: they are not user input
	_, err := database.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s;", table, column, columnType))
	return err
}

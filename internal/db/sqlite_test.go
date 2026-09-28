package db

import (
	"database/sql"
	"fmt"
	"sync"
	"testing"
)

func TestMigrateAddsAuthTimeToOldDatabases(t *testing.T) {
	path := t.TempDir() + "/old.sqlite3"
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}

	_, err = old.Exec(`CREATE TABLE sessions (id TEXT PRIMARY KEY, userID TEXT NOT NULL, requireMFA INTEGER DEFAULT 1, expiresAt DATETIME NOT NULL);
	CREATE TABLE grants (id TEXT PRIMARY KEY, grantType TEXT NOT NULL, clientID TEXT NOT NULL, sessionID TEXT NOT NULL, expiresAt DATETIME NOT NULL, scopes TEXT NOT NULL, nonce TEXT, codeChallenge TEXT, codeChallengeMethod TEXT);`)
	if err != nil {
		t.Fatal(err)
	}
	old.Close()

	database, err := NewSqliteDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if _, err := database.Exec("INSERT INTO sessions(id, userID, expiresAt, authTime, mfaVerified) VALUES('1', '1', datetime('now'), datetime('now'), 1);"); err != nil {
		t.Fatalf("Expected authTime column: %v", err)
	}

	if _, err := database.Exec("INSERT INTO grants(id, grantType, clientID, sessionID, expiresAt, scopes, redirectURI, familyID, used) VALUES('1', 'code', '1', '1', datetime('now'), 'openid', 'http://client.test', '1', 0);"); err != nil {
		t.Fatalf("Expected redirectURI column: %v", err)
	}

	// running it again must not fail
	if err := migrate(database); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentWrites(t *testing.T) {
	database, err := NewSqliteDB(t.TempDir() + "/concurrent.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	errs := make(chan error, 100)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := database.Exec("INSERT INTO client_assertions(id, expiresAt) VALUES(?, ?);", fmt.Sprint("id", i), i)
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("Expected concurrent writes to wait for the lock: %v", err)
		}
	}
}

package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/fernandoescolar/minioidc/pkg/cryptography"
)

const (
	defaultDatabaseFile  = "minioidc.sqlite3"
	defaultMasterKeyFile = "masterkey"
	defaultKeyFile       = "private.pem"
)

// NewDefaultBuilder is the configuration of a server without a configuration
// file: the users, the clients and the rest of the data in SQLite, and the
// administration enabled. The master key and the signing key are generated on
// the first start. Everything is kept in dataDir, so it survives the restarts.
// The CSP is enabled, and with an https issuer, the secure cookies and HSTS.
func NewDefaultBuilder(dataDir, issuer string) (*Builder, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("data directory: %w", err)
	}

	masterKey, err := loadOrCreate(filepath.Join(dataDir, defaultMasterKeyFile), func() ([]byte, error) {
		key, err := cryptography.RandomPassword(cryptography.MinMasterKeyLength)
		return []byte(key + "\n"), err
	})
	if err != nil {
		return nil, fmt.Errorf("master key: %w", err)
	}

	keyPath := filepath.Join(dataDir, defaultKeyFile)
	if _, err := loadOrCreate(keyPath, newPrivateKeyPEM); err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}

	https := strings.HasPrefix(issuer, "https://")
	builder := &Builder{
		Issuer:                issuer,
		Audience:              issuer,
		MasterKey:             strings.TrimSpace(string(masterKey)),
		PrivateRSAKeyFilepath: keyPath,
		AdminEnabled:          true,
		DataDir:               dataDir,
		UseCSP:                true,
		UseSecureCookie:       https,
		UseHSTS:               https,
	}
	builder.UseSQLite(filepath.Join(dataDir, defaultDatabaseFile), All)

	return builder, nil
}

// loadOrCreate reads the file, or creates it (only readable by the owner) with
// the content of create
func loadOrCreate(path string, create func() ([]byte, error)) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err == nil {
		return content, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	if content, err = create(); err != nil {
		return nil, err
	}

	if err := os.WriteFile(path, content, 0o600); err != nil {
		return nil, err
	}

	return content, nil
}

func newPrivateKeyPEM() ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, defaultRSASize)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), nil
}

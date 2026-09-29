package stores

import (
	"crypto"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

const clientColumns = "id, secretHash, encryptedSecret, redirectURIs, postLogoutRedirectURIs, authMethod, jwksURI, publicKeys, grantTypes"

type sqlClientStore struct {
	db        *sql.DB
	masterKey string
}

// NewSqliteClientStore initializes a ClientStore in SQLite that can be managed
// from the admin web. The plain secrets (client_secret_jwt) are encrypted with the master key.
func NewSqliteClientStore(db *sql.DB, masterKey string) domain.ClientAdminStore {
	return &sqlClientStore{db: db, masterKey: masterKey}
}

func (cs *sqlClientStore) NewClient(data domain.ClientData) (domain.Client, error) {
	values, err := cs.values(data)
	if err != nil {
		return nil, err
	}

	_, err = cs.db.Exec("INSERT INTO clients("+clientColumns+") VALUES(?,?,?,?,?,?,?,?,?);", values...)
	if err != nil {
		return nil, fmt.Errorf("NewClient: %w", err)
	}

	return domain.NewClient(data), nil
}

func (cs *sqlClientStore) GetClientByID(id string) (domain.Client, error) {
	row := cs.db.QueryRow("SELECT "+clientColumns+" FROM clients WHERE id = ?;", id)
	data, err := cs.scan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("client not found")
	}
	if err != nil {
		return nil, err
	}

	return domain.NewClient(*data), nil
}

func (cs *sqlClientStore) ListClients() ([]domain.ClientData, error) {
	rows, err := cs.db.Query("SELECT " + clientColumns + " FROM clients ORDER BY id;")
	if err != nil {
		return nil, fmt.Errorf("ListClients: %w", err)
	}
	defer rows.Close()

	clients := []domain.ClientData{}
	for rows.Next() {
		data, err := cs.scan(rows)
		if err != nil {
			return nil, fmt.Errorf("ListClients: %w", err)
		}

		clients = append(clients, *data)
	}

	return clients, rows.Err()
}

func (cs *sqlClientStore) UpdateClient(data domain.ClientData) error {
	values, err := cs.values(data)
	if err != nil {
		return err
	}

	// the id goes at the end, for the WHERE
	values = append(values[1:], data.ID)
	r, err := cs.db.Exec(`UPDATE clients SET secretHash = ?, encryptedSecret = ?, redirectURIs = ?, postLogoutRedirectURIs = ?,
		authMethod = ?, jwksURI = ?, publicKeys = ?, grantTypes = ? WHERE id = ?;`, values...)
	if err != nil {
		return fmt.Errorf("UpdateClient: %w", err)
	}

	return expectOneRow(r, "client")
}

func (cs *sqlClientStore) DeleteClient(id string) error {
	r, err := cs.db.Exec("DELETE FROM clients WHERE id = ?;", id)
	if err != nil {
		return fmt.Errorf("DeleteClient: %w", err)
	}

	return expectOneRow(r, "client")
}

// values returns the column values of a valid client, in the order of clientColumns
func (cs *sqlClientStore) values(data domain.ClientData) ([]interface{}, error) {
	if err := domain.ValidateClientData(data); err != nil {
		return nil, err
	}

	encryptedSecret := ""
	if data.Secret != "" {
		var err error
		if encryptedSecret, err = cryptography.Encrypts(cs.masterKey, data.Secret); err != nil {
			return nil, err
		}
	}

	publicKeys := []string{}
	for _, key := range data.PublicKeys {
		encoded, err := cryptography.EncodePublicKeyPEM(key)
		if err != nil {
			return nil, fmt.Errorf("client %s: %w", data.ID, err)
		}

		publicKeys = append(publicKeys, encoded)
	}

	redirectURIs, _ := json.Marshal(nonNil(data.RedirectURIs))
	postLogoutRedirectURIs, _ := json.Marshal(nonNil(data.PostLogoutRedirectURIs))
	keys, _ := json.Marshal(publicKeys)
	grantTypes, _ := json.Marshal(nonNil(data.GrantTypes))

	return []interface{}{
		data.ID, data.SecretHash, encryptedSecret, string(redirectURIs), string(postLogoutRedirectURIs),
		data.TokenEndpointAuthMethod, data.JWKSURI, string(keys), string(grantTypes),
	}, nil
}

func (cs *sqlClientStore) scan(row scanner) (*domain.ClientData, error) {
	data := &domain.ClientData{}
	var encryptedSecret, redirectURIs, postLogoutRedirectURIs, publicKeys, grantTypes string
	err := row.Scan(&data.ID, &data.SecretHash, &encryptedSecret, &redirectURIs, &postLogoutRedirectURIs,
		&data.TokenEndpointAuthMethod, &data.JWKSURI, &publicKeys, &grantTypes)
	if err != nil {
		return nil, err
	}

	if encryptedSecret != "" {
		if data.Secret, err = cryptography.Decrypts(cs.masterKey, encryptedSecret); err != nil {
			return nil, fmt.Errorf("client %s: the secret cannot be decrypted (has the masterkey changed?)", data.ID)
		}
	}

	var pems []string
	for target, value := range map[*[]string]string{
		&data.RedirectURIs: redirectURIs, &data.PostLogoutRedirectURIs: postLogoutRedirectURIs, &pems: publicKeys, &data.GrantTypes: grantTypes,
	} {
		if err := json.Unmarshal([]byte(value), target); err != nil {
			return nil, fmt.Errorf("client %s: %w", data.ID, err)
		}
	}

	for _, encoded := range pems {
		key, err := cryptography.ParsePublicKeyPEM([]byte(encoded))
		if err != nil {
			return nil, fmt.Errorf("client %s: %w", data.ID, err)
		}

		data.PublicKeys = append(data.PublicKeys, crypto.PublicKey(key))
	}

	return data, nil
}

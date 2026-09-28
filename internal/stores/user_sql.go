package stores

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

const userColumns = "subject, preferredUsername, email, emailVerified, name, givenName, familyName, phone, address, groups, passwordHash"

type sqlUserStore struct {
	db *sql.DB
}

// NewSqliteUserStore initializes a UserStore in SQLite that can be managed from the admin web
func NewSqliteUserStore(db *sql.DB) domain.UserAdminStore {
	return &sqlUserStore{db: db}
}

func (us *sqlUserStore) NewUser(data domain.UserData) (domain.User, error) {
	if err := validateUserData(data); err != nil {
		return nil, err
	}

	groups, err := json.Marshal(nonNil(data.Groups))
	if err != nil {
		return nil, err
	}

	_, err = us.db.Exec("INSERT INTO users("+userColumns+") VALUES(?,?,?,?,?,?,?,?,?,?,?);",
		data.Subject, data.PreferredUsername, data.Email, data.EmailVerified, data.Name, data.GivenName, data.FamilyName,
		data.Phone, data.Address, string(groups), data.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("NewUser: %w", err)
	}

	return domain.NewUser(data), nil
}

func (us *sqlUserStore) GetUserByID(id string) (domain.User, error) {
	data, err := us.get("subject", id)
	if err != nil {
		return nil, err
	}

	return domain.NewUser(*data), nil
}

func (us *sqlUserStore) GetUserByUsernameAndPassword(username string, password string) (domain.User, error) {
	data, err := us.get("preferredUsername", username)
	if err != nil {
		cryptography.CheckPasswordHash(password, dummyPasswordHash)
		return nil, err
	}

	user := domain.NewUser(*data)
	if data.PasswordHash == "" || !user.PasswordIsValid(password) {
		return nil, errors.New("user not found")
	}

	return user, nil
}

func (us *sqlUserStore) ListUsers() ([]domain.UserData, error) {
	rows, err := us.db.Query("SELECT " + userColumns + " FROM users ORDER BY preferredUsername;")
	if err != nil {
		return nil, fmt.Errorf("ListUsers: %w", err)
	}
	defer rows.Close()

	users := []domain.UserData{}
	for rows.Next() {
		data, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("ListUsers: %w", err)
		}

		users = append(users, *data)
	}

	return users, rows.Err()
}

func (us *sqlUserStore) UpdateUser(data domain.UserData) error {
	if err := validateUserData(data); err != nil {
		return err
	}

	groups, err := json.Marshal(nonNil(data.Groups))
	if err != nil {
		return err
	}

	// an empty password hash keeps the current password
	r, err := us.db.Exec(`UPDATE users SET preferredUsername = ?, email = ?, emailVerified = ?, name = ?, givenName = ?, familyName = ?,
		phone = ?, address = ?, groups = ?, passwordHash = CASE WHEN ? = '' THEN passwordHash ELSE ? END WHERE subject = ?;`,
		data.PreferredUsername, data.Email, data.EmailVerified, data.Name, data.GivenName, data.FamilyName,
		data.Phone, data.Address, string(groups), data.PasswordHash, data.PasswordHash, data.Subject)
	if err != nil {
		return fmt.Errorf("UpdateUser: %w", err)
	}

	return expectOneRow(r, "user")
}

func (us *sqlUserStore) DeleteUser(id string) error {
	r, err := us.db.Exec("DELETE FROM users WHERE subject = ?;", id)
	if err != nil {
		return fmt.Errorf("DeleteUser: %w", err)
	}

	return expectOneRow(r, "user")
}

func (us *sqlUserStore) get(column, value string) (*domain.UserData, error) {
	row := us.db.QueryRow("SELECT "+userColumns+" FROM users WHERE "+column+" = ?;", value)
	data, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("user not found")
	}

	return data, err
}

type scanner interface {
	Scan(dest ...interface{}) error
}

func scanUser(row scanner) (*domain.UserData, error) {
	data := &domain.UserData{}
	var groups string
	err := row.Scan(&data.Subject, &data.PreferredUsername, &data.Email, &data.EmailVerified, &data.Name, &data.GivenName,
		&data.FamilyName, &data.Phone, &data.Address, &groups, &data.PasswordHash)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(groups), &data.Groups); err != nil {
		return nil, fmt.Errorf("invalid groups of user %s: %w", data.Subject, err)
	}

	return data, nil
}

func validateUserData(data domain.UserData) error {
	if data.Subject == "" || data.PreferredUsername == "" {
		return errors.New("the user subject and preferred_username are required")
	}

	return nil
}

func expectOneRow(r sql.Result, entity string) error {
	rows, err := r.RowsAffected()
	if err != nil {
		return err
	}

	if rows != 1 {
		return fmt.Errorf("%s not found", entity)
	}

	return nil
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}

	return values
}

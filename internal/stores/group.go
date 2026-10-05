package stores

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type miniGroupStore struct {
	mu     sync.RWMutex
	groups map[string]domain.Group
}

// NewGroupStore initializes a GroupStore in memory
func NewGroupStore() domain.GroupStore {
	return &miniGroupStore{groups: map[string]domain.Group{}}
}

func (s *miniGroupStore) ListGroups() ([]domain.Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	groups := make([]domain.Group, 0, len(s.groups))
	for _, g := range s.groups {
		groups = append(groups, g)
	}

	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	return groups, nil
}

func (s *miniGroupStore) GetGroup(name string) (domain.Group, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.groups[name]
	return g, ok, nil
}

func (s *miniGroupStore) SaveGroup(group domain.Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.groups[group.Name]; ok && group.CreatedAt.IsZero() {
		group.CreatedAt = existing.CreatedAt
	}
	s.groups[group.Name] = group
	return nil
}

func (s *miniGroupStore) RenameGroup(oldName, newName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g, ok := s.groups[oldName]; ok {
		delete(s.groups, oldName)
		g.Name = newName
		s.groups[newName] = g
	}

	return nil
}

func (s *miniGroupStore) DeleteGroup(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.groups, name)
	return nil
}

type sqlGroupStore struct {
	db *sql.DB
}

// NewSqliteGroupStore initializes a GroupStore in SQLite
func NewSqliteGroupStore(db *sql.DB) domain.GroupStore {
	return &sqlGroupStore{db: db}
}

func (s *sqlGroupStore) ListGroups() ([]domain.Group, error) {
	rows, err := s.db.Query("SELECT name, description, createdAt FROM groups ORDER BY name;")
	if err != nil {
		return nil, fmt.Errorf("ListGroups: %w", err)
	}
	defer rows.Close()

	groups := []domain.Group{}
	for rows.Next() {
		var (
			g  domain.Group
			ms int64
		)
		if err := rows.Scan(&g.Name, &g.Description, &ms); err != nil {
			return nil, fmt.Errorf("ListGroups: %w", err)
		}
		g.CreatedAt = fromUnixMilli(ms)
		groups = append(groups, g)
	}

	return groups, rows.Err()
}

func (s *sqlGroupStore) GetGroup(name string) (domain.Group, bool, error) {
	var (
		g  domain.Group
		ms int64
	)
	err := s.db.QueryRow("SELECT name, description, createdAt FROM groups WHERE name = ?;", name).Scan(&g.Name, &g.Description, &ms)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Group{}, false, nil
	}
	if err != nil {
		return domain.Group{}, false, fmt.Errorf("GetGroup: %w", err)
	}

	g.CreatedAt = fromUnixMilli(ms)
	return g, true, nil
}

func (s *sqlGroupStore) SaveGroup(group domain.Group) error {
	if group.CreatedAt.IsZero() {
		group.CreatedAt = time.Now()
	}

	// the creation date of an existing group is kept
	_, err := s.db.Exec(`INSERT INTO groups(name, description, createdAt) VALUES(?,?,?)
		ON CONFLICT(name) DO UPDATE SET description = excluded.description;`, group.Name, group.Description, group.CreatedAt.UnixMilli())
	if err != nil {
		return fmt.Errorf("SaveGroup: %w", err)
	}

	return nil
}

func (s *sqlGroupStore) RenameGroup(oldName, newName string) error {
	_, err := s.db.Exec("UPDATE groups SET name = ? WHERE name = ?;", newName, oldName)
	return err
}

func (s *sqlGroupStore) DeleteGroup(name string) error {
	_, err := s.db.Exec("DELETE FROM groups WHERE name = ?;", name)
	return err
}

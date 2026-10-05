package domain

import "time"

// Group is the definition of a group: its description. The members are in
// the groups of each user, and the groups that the users have are groups too,
// even without a definition.
type Group struct {
	Name        string
	Description string
	CreatedAt   time.Time
}

type GroupStore interface {
	// ListGroups returns the definitions, sorted by name
	ListGroups() ([]Group, error)
	GetGroup(name string) (Group, bool, error)
	// SaveGroup creates or updates the definition of a group
	SaveGroup(group Group) error
	// RenameGroup changes the name of a definition (if it exists)
	RenameGroup(oldName, newName string) error
	DeleteGroup(name string) error
}

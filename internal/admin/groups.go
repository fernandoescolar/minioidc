package admin

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"unicode"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

const maxGroupName = 64

type groupDTO struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Members     int    `json:"members"`
	// Admin is true for the group of the administrators
	Admin bool `json:"admin"`
	// Clients are the clients restricted to this group
	Clients []string `json:"clients"`
	// Defined is false for the groups that only exist in the users
	Defined bool `json:"defined"`
}

type groupInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type membersInput struct {
	Subjects []string `json:"subjects"`
}

// cleanGroups trims the names and removes the empty and repeated ones
func cleanGroups(groups []string) []string {
	result := []string{}
	seen := map[string]bool{}
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g != "" && !seen[strings.ToLower(g)] {
			seen[strings.ToLower(g)] = true
			result = append(result, g)
		}
	}

	sort.Strings(result)
	return result
}

// validateGroupName checks a group name: it is a path segment of the admin
// API and a claim of the tokens
func validateGroupName(name string) error {
	if name == "" || len([]rune(name)) > maxGroupName {
		return fmt.Errorf("the group name must have between 1 and %d characters", maxGroupName)
	}

	for _, r := range name {
		if r == '/' || r == ',' || unicode.IsControl(r) {
			return fmt.Errorf("the group name %q cannot have slashes, commas or control characters", name)
		}
	}

	return nil
}

// groupsManageable returns false (and writes the error) when the groups of
// the users cannot be changed (LDAP, the users of the configuration)
func (h *Handler) groupsManageable(w http.ResponseWriter) bool {
	if h.users == nil {
		writeError(w, http.StatusMethodNotAllowed, "the groups are read only: the users are managed in the configuration or in LDAP")
		return false
	}

	return true
}

func (h *Handler) allUsers() ([]domain.UserData, error) {
	if h.lister == nil {
		return nil, nil
	}

	return h.lister.ListUsers()
}

func (h *Handler) listGroups(w http.ResponseWriter, _ *http.Request) {
	users, err := h.allUsers()
	if err != nil {
		writeInternalError(w, err)
		return
	}

	clients, err := h.clients.ListClients()
	if err != nil {
		writeInternalError(w, err)
		return
	}

	definitions, err := h.groupStore.ListGroups()
	if err != nil {
		writeInternalError(w, err)
		return
	}

	// the groups of the definitions, the users and the clients (by lower case name)
	groups := map[string]*groupDTO{}
	group := func(name string) *groupDTO {
		key := strings.ToLower(name)
		if groups[key] == nil {
			groups[key] = &groupDTO{Name: name, Clients: []string{}, Admin: strings.EqualFold(name, h.adminGroup)}
		}
		return groups[key]
	}

	for _, d := range definitions {
		g := group(d.Name)
		g.Name, g.Description, g.Defined = d.Name, d.Description, true
	}
	for _, u := range users {
		for _, name := range cleanGroups(u.Groups) {
			group(name).Members++
		}
	}
	for _, c := range clients {
		for _, name := range c.AllowedGroups {
			g := group(name)
			g.Clients = append(g.Clients, c.ID)
		}
	}
	group(h.adminGroup)

	result := make([]groupDTO, 0, len(groups))
	for _, g := range groups {
		result = append(result, *g)
	}
	sort.Slice(result, func(i, j int) bool { return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name) })
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) createGroup(w http.ResponseWriter, r *http.Request) {
	if !h.groupsManageable(w) {
		return
	}

	var input groupInput
	if !readJSON(w, r, &input) {
		return
	}

	input.Name = strings.TrimSpace(input.Name)
	if err := validateGroupName(input.Name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if exists, err := h.groupExists(input.Name, ""); err != nil {
		writeInternalError(w, err)
		return
	} else if exists {
		writeError(w, http.StatusConflict, "a group with this name already exists")
		return
	}

	group := domain.Group{Name: input.Name, Description: strings.TrimSpace(input.Description), CreatedAt: h.now()}
	if err := h.groupStore.SaveGroup(group); err != nil {
		writeInternalError(w, err)
		return
	}

	h.audit(r, domain.EventAdminGroup, nil, "", "created "+group.Name)
	writeJSON(w, http.StatusCreated, groupDTO{Name: group.Name, Description: group.Description, Clients: []string{}, Defined: true})
}

// updateGroup changes the description and renames the group in its users and clients
func (h *Handler) updateGroup(w http.ResponseWriter, r *http.Request) {
	if !h.groupsManageable(w) {
		return
	}

	var input groupInput
	if !readJSON(w, r, &input) {
		return
	}

	name := r.PathValue("name")
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		input.Name = name
	}
	if err := validateGroupName(input.Name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	renamed := input.Name != name
	if renamed {
		// the name of the admin group is in the configuration
		if strings.EqualFold(name, h.adminGroup) || strings.EqualFold(input.Name, h.adminGroup) {
			writeError(w, http.StatusBadRequest, "the admin group cannot be renamed (it is admin.group in the configuration)")
			return
		}

		if exists, err := h.groupExists(input.Name, name); err != nil {
			writeInternalError(w, err)
			return
		} else if exists {
			writeError(w, http.StatusConflict, "a group with this name already exists")
			return
		}

		if err := h.renameInUsersAndClients(name, input.Name); err != nil {
			writeInternalError(w, err)
			return
		}
		if err := h.groupStore.RenameGroup(name, input.Name); err != nil {
			writeInternalError(w, err)
			return
		}
	}

	existing, _, err := h.groupStore.GetGroup(input.Name)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	existing.Name, existing.Description = input.Name, strings.TrimSpace(input.Description)
	if existing.CreatedAt.IsZero() {
		existing.CreatedAt = h.now()
	}
	if err := h.groupStore.SaveGroup(existing); err != nil {
		writeInternalError(w, err)
		return
	}

	detail := "updated " + input.Name
	if renamed {
		detail = "renamed " + name + " to " + input.Name
	}
	h.audit(r, domain.EventAdminGroup, nil, "", detail)
	w.WriteHeader(http.StatusNoContent)
}

// deleteGroup removes the group from its members. The groups of the clients
// cannot be deleted: a client without groups would be open to all the users.
func (h *Handler) deleteGroup(w http.ResponseWriter, r *http.Request) {
	if !h.groupsManageable(w) {
		return
	}

	name := r.PathValue("name")
	if strings.EqualFold(name, h.adminGroup) {
		writeError(w, http.StatusBadRequest, "the admin group cannot be deleted")
		return
	}

	clients, err := h.clients.ListClients()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	var users []string
	for _, c := range clients {
		if containsFold(c.AllowedGroups, name) {
			users = append(users, c.ID)
		}
	}
	if len(users) > 0 {
		writeError(w, http.StatusConflict, "the group is used by the clients "+strings.Join(users, ", ")+": remove it from them first")
		return
	}

	if err := h.renameInUsersAndClients(name, ""); err != nil {
		writeInternalError(w, err)
		return
	}
	if err := h.groupStore.DeleteGroup(name); err != nil {
		writeInternalError(w, err)
		return
	}

	h.audit(r, domain.EventAdminGroup, nil, "", "deleted "+name)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listMembers(w http.ResponseWriter, r *http.Request) {
	users, err := h.allUsers()
	if err != nil {
		writeInternalError(w, err)
		return
	}

	name := r.PathValue("name")
	members := []userDTO{}
	for _, u := range users {
		if containsFold(u.Groups, name) {
			members = append(members, h.userDTO(u))
		}
	}

	writeJSON(w, http.StatusOK, members)
}

func (h *Handler) addMembers(w http.ResponseWriter, r *http.Request) {
	if !h.groupsManageable(w) {
		return
	}

	name := r.PathValue("name")
	if err := validateGroupName(name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// the administrators can do anything: adding one needs a recent login
	if strings.EqualFold(name, h.adminGroup) && !h.requireRecentLogin(w, r) {
		return
	}

	var input membersInput
	if !readJSON(w, r, &input) {
		return
	}

	// the group keeps the name of its definition
	if g, ok, err := h.groupStore.GetGroup(name); err == nil && ok {
		name = g.Name
	}

	for _, subject := range input.Subjects {
		user, err := h.userStore.GetUserByID(subject)
		if err != nil {
			writeError(w, http.StatusNotFound, "user not found: "+subject)
			return
		}

		data := user.Data()
		if containsFold(data.Groups, name) {
			continue
		}

		data.Groups = cleanGroups(append(data.Groups, name))
		data.PasswordHash = ""
		if err := h.users.UpdateUser(data); err != nil {
			writeStoreError(w, err)
			return
		}
		h.audit(r, domain.EventAdminGroup, user, "", "added to "+name)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) removeMember(w http.ResponseWriter, r *http.Request) {
	if !h.groupsManageable(w) {
		return
	}

	name := r.PathValue("name")
	user, err := h.userStore.GetUserByID(r.PathValue("subject"))
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	if strings.EqualFold(name, h.adminGroup) && user.ID() == adminFromContext(r).ID() {
		writeError(w, http.StatusBadRequest, "you cannot remove yourself from the admin group")
		return
	}

	data := user.Data()
	if !containsFold(data.Groups, name) {
		writeError(w, http.StatusNotFound, "the user is not a member of the group")
		return
	}

	data.Groups = removeFold(data.Groups, name)
	data.PasswordHash = ""
	if err := h.users.UpdateUser(data); err != nil {
		writeStoreError(w, err)
		return
	}

	h.audit(r, domain.EventAdminGroup, user, "", "removed from "+name)
	w.WriteHeader(http.StatusNoContent)
}

// groupExists returns true if there is a group with the name (ignoring the
// case), except the group except (a rename that only changes the case)
func (h *Handler) groupExists(name, except string) (bool, error) {
	if strings.EqualFold(name, except) {
		return false, nil
	}
	if strings.EqualFold(name, h.adminGroup) {
		return true, nil
	}

	definitions, err := h.groupStore.ListGroups()
	if err != nil {
		return false, err
	}
	for _, d := range definitions {
		if strings.EqualFold(d.Name, name) {
			return true, nil
		}
	}

	users, err := h.allUsers()
	if err != nil {
		return false, err
	}
	for _, u := range users {
		if containsFold(u.Groups, name) {
			return true, nil
		}
	}

	return false, nil
}

// renameInUsersAndClients replaces the group in the users and the allowed
// groups of the clients. An empty newName removes it.
func (h *Handler) renameInUsersAndClients(oldName, newName string) error {
	users, err := h.allUsers()
	if err != nil {
		return err
	}

	for _, u := range users {
		if !containsFold(u.Groups, oldName) {
			continue
		}

		groups := removeFold(u.Groups, oldName)
		if newName != "" {
			groups = cleanGroups(append(groups, newName))
		}
		u.Groups = groups
		u.PasswordHash = ""
		if err := h.users.UpdateUser(u); err != nil {
			return fmt.Errorf("user %s: %w", u.PreferredUsername, err)
		}
	}

	clients, err := h.clients.ListClients()
	if err != nil {
		return err
	}

	for _, c := range clients {
		if !containsFold(c.AllowedGroups, oldName) {
			continue
		}

		if newName == "" {
			// deleteGroup does not delete the groups of the clients
			return errors.New("the group is used by the client " + c.ID)
		}
		c.AllowedGroups = cleanGroups(append(removeFold(c.AllowedGroups, oldName), newName))
		if err := h.clients.UpdateClient(c); err != nil {
			return fmt.Errorf("client %s: %w", c.ID, err)
		}
	}

	return nil
}

func containsFold(list []string, value string) bool {
	for _, element := range list {
		if strings.EqualFold(element, value) {
			return true
		}
	}

	return false
}

func removeFold(list []string, value string) []string {
	result := []string{}
	for _, element := range list {
		if !strings.EqualFold(element, value) {
			result = append(result, element)
		}
	}

	return result
}

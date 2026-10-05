package admin

import (
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/fernandoescolar/minioidc/internal/settings"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type settingDTO struct {
	Key         string `json:"key"`
	Group       string `json:"group"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	Kind        string `json:"kind"`
	Min         int    `json:"min,omitempty"`
	Max         int    `json:"max,omitempty"`
	Default     string `json:"default"`
	// Value is the value of the file (or the running one without a file)
	Value string `json:"value"`
	// Running is the value that the server is using
	Running string `json:"running"`
	// FromEnv is true when the file reads it from an environment variable
	FromEnv bool `json:"from_env"`
	// Pending is true when the file has a value that needs a restart
	Pending bool `json:"pending"`
}

type infoItem struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type settingsDTO struct {
	// Mode is "file" with a configuration file and "default" without it
	Mode     string `json:"mode"`
	File     string `json:"file,omitempty"`
	DataDir  string `json:"data_dir,omitempty"`
	Editable bool   `json:"editable"`
	// ReadOnlyReason explains why the settings cannot be edited
	ReadOnlyReason string       `json:"read_only_reason,omitempty"`
	Version        string       `json:"version,omitempty"`
	Settings       []settingDTO `json:"settings"`
	Server         []infoItem   `json:"server"`
}

type settingsInput struct {
	Version string            `json:"version"`
	Values  map[string]string `json:"values"`
}

func (h *Handler) getSettings(w http.ResponseWriter, _ *http.Request) {
	dto, err := h.settings()
	if err != nil {
		writeInternalError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, dto)
}

// settings reads the settings of the file and the running ones
func (h *Handler) settings() (settingsDTO, error) {
	dto := settingsDTO{Mode: "default", DataDir: h.config.DataDir, Server: h.serverInfo()}
	var file *settings.File
	if path := h.config.ConfigFilepath; path != "" {
		dto.Mode, dto.File = "file", path
		var err error
		if file, err = settings.Read(path); err != nil {
			return dto, err
		}
		dto.Version = file.Version
		if err := settings.Writable(path); err != nil {
			dto.ReadOnlyReason = "The server cannot write the configuration file (" + err.Error() + "). Edit it by hand, or give the server write access."
		} else {
			dto.Editable = true
		}
	} else {
		dto.ReadOnlyReason = "The server runs without a configuration file. Download the configuration below to start using one."
	}

	for _, d := range settings.Definitions {
		running := d.Running(h.config)
		s := settingDTO{
			Key: d.Key, Group: d.Group, Label: d.Label, Description: d.Description, Kind: string(d.Kind),
			Min: d.Min, Max: d.Max, Default: d.Default, Value: running, Running: running,
		}
		if file != nil {
			value, present, fromEnv := file.Get(d.Key)
			switch {
			case fromEnv:
				s.Value, s.FromEnv = value, true
			case present:
				// the file values are normalized, so "yes" and "true" are not a change
				if normalized, err := d.Validate(value); err == nil {
					value = normalized
				}
				s.Value = value
			default:
				s.Value = d.Default
			}
			s.Pending = !s.FromEnv && s.Value != running
		}
		dto.Settings = append(dto.Settings, s)
	}

	return dto, nil
}

// updateSettings writes the settings in the configuration file. They apply
// when the server restarts.
func (h *Handler) updateSettings(w http.ResponseWriter, r *http.Request) {
	if !h.requireRecentLogin(w, r) {
		return
	}

	var input settingsInput
	if !readJSON(w, r, &input) {
		return
	}

	path := h.config.ConfigFilepath
	if path == "" {
		writeError(w, http.StatusMethodNotAllowed, "the server runs without a configuration file")
		return
	}
	if err := settings.Writable(path); err != nil {
		writeError(w, http.StatusMethodNotAllowed, "the server cannot write the configuration file")
		return
	}

	file, err := settings.Read(path)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if input.Version != file.Version {
		writeError(w, http.StatusConflict, settings.ErrConflict.Error())
		return
	}

	keys := make([]string, 0, len(input.Values))
	for key := range input.Values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var changes []string
	for _, key := range keys {
		d, ok := settings.Find(key)
		if !ok {
			writeError(w, http.StatusBadRequest, "the setting "+key+" cannot be changed here")
			return
		}

		value, err := d.Validate(input.Values[key])
		if err == nil {
			err = d.CheckIssuer(value, h.config.Issuer)
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		current, present, _ := file.Get(key)
		if normalized, err := d.Validate(current); err == nil {
			current = normalized
		}
		if !present {
			current = d.Default
		}
		if current == value {
			continue
		}

		if err := file.Set(d, value); err != nil {
			if errors.Is(err, settings.ErrFromEnv) {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			writeInternalError(w, err)
			return
		}
		changes = append(changes, fmt.Sprintf("%s=%s", key, value))
	}

	if len(changes) > 0 {
		if err := file.Save(); err != nil {
			if errors.Is(err, settings.ErrConflict) {
				writeError(w, http.StatusConflict, err.Error())
				return
			}
			writeInternalError(w, err)
			return
		}
		h.audit(r, domain.EventAdminSettings, nil, "", strings.Join(changes, ", "))
	}

	h.getSettings(w, r)
}

// exportSettings downloads a configuration file with the running settings of
// the default configuration
func (h *Handler) exportSettings(w http.ResponseWriter, _ *http.Request) {
	if h.config.ConfigFilepath != "" {
		writeError(w, http.StatusNotFound, "the server already uses a configuration file")
		return
	}

	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="minioidc.yml"`)
	_, _ = w.Write(settings.Generate(h.config))
}

// serverInfo are the settings that are only changed in the file
func (h *Handler) serverInfo() []infoItem {
	users := "LDAP"
	switch {
	case h.users != nil:
		users = "SQLite (managed here)"
	case h.lister != nil:
		users = "The configuration file"
	}

	items := []infoItem{
		{"Issuer", h.config.Issuer},
		{"Audience", h.config.Audience},
		{"Administrators group", h.adminGroup},
		{"Users", users},
	}
	if h.config.SqliteFilepath != "" {
		items = append(items, infoItem{"Database", h.config.SqliteFilepath})
	}
	if h.config.DataDir != "" {
		items = append(items, infoItem{"Data directory", h.config.DataDir})
	}
	if h.config.LDAPServer != nil {
		items = append(items, infoItem{"LDAP server", h.config.LDAPServer.Address})
	}
	if kid, err := h.config.Keypair.KeyID(); err == nil {
		items = append(items, infoItem{"Signing key (kid)", kid})
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		items = append(items, infoItem{"Version", info.Main.Version + " (" + info.GoVersion + ")"})
	}

	return items
}

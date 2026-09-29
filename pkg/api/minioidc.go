package api

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/router"
	"github.com/fernandoescolar/minioidc/internal/ldapserver"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

const cleanInterval = time.Hour

type Minioidc struct {
	Now    func() time.Time
	config *domain.Config

	stop     chan struct{}
	stopOnce sync.Once
	ldap     *ldapserver.Server
}

// NewMinioidc creates a new Minioidc instance.
func NewMinioidc(config *domain.Config) *Minioidc {
	return &Minioidc{
		Now:    time.Now,
		config: config,
		stop:   make(chan struct{}),
	}
}

// Handler returns the Minioidc handler.
func (m *Minioidc) Handler() http.Handler {
	mux := http.NewServeMux()
	return m.Wrap(mux)
}

// Wrap adds the Minioidc routes to the provided ServeMux and starts the
// background job that removes expired data. Call Close to stop it.
func (m *Minioidc) Wrap(mux *http.ServeMux) http.Handler {
	go m.cleanPeriodically()

	return router.CreateMinioidcRoutes(mux, m.config, m.Now)
}

// StartLDAPServer starts the LDAP server, if it is configured. It returns
// when the server is listening.
func (m *Minioidc) StartLDAPServer() error {
	if m.config.LDAPServer == nil || m.ldap != nil {
		return nil
	}

	server, err := ldapserver.New(m.config, m.Now)
	if err != nil {
		return err
	}

	if err := server.Start(); err != nil {
		return err
	}

	m.ldap = server
	return nil
}

// Close stops the background jobs and the LDAP server.
func (m *Minioidc) Close() {
	m.stopOnce.Do(func() {
		close(m.stop)
		if m.ldap != nil {
			if err := m.ldap.Stop(); err != nil {
				log.Printf("stopping the LDAP server: %v", err)
			}
		}
	})
}

// Config returns the Minioidc configuration.
func (m *Minioidc) Config() *domain.Config {
	return m.config
}

// CleanExpired removes expired sessions, grants and blocks from the stores.
func (m *Minioidc) CleanExpired() {
	m.config.SessionStore.CleanExpired()
	m.config.GrantStore.CleanExpired()
	m.config.UserBlockedStore.CleanExpired(m.Now())
	m.config.ClientAssertionStore.CleanExpired(m.Now())
	m.config.DeviceCodeStore.CleanExpired(m.Now())
	log.Println("CleanExpired: Expired sessions and grants have been removed")
}

func (m *Minioidc) cleanPeriodically() {
	ticker := time.NewTicker(cleanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.CleanExpired()
		case <-m.stop:
			return
		}
	}
}

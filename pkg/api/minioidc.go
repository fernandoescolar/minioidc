package api

import (
	"log"
	"net/http"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/router"
	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/go-co-op/gocron"
)

type Minioidc struct {
	Now    func() time.Time
	config *domain.Config
}

// NewMinioidc creates a new Minioidc instance.
func NewMinioidc(config *domain.Config) *Minioidc {
	return &Minioidc{
		Now:    time.Now,
		config: config,
	}
}

// Handler returns the Minioidc handler.
func (m *Minioidc) Handler() http.Handler {
	mux := http.NewServeMux()
	return m.Wrap(mux)
}

// Wrap adds the Minioidc routes to the provided ServeMux.
func (m *Minioidc) Wrap(mux *http.ServeMux) http.Handler {
	scheduler := gocron.NewScheduler(time.UTC)
	_, err := scheduler.Every(1).Hour().Do(m.CleanExpired)
	if err != nil {
		log.Println("CleanExpired job has not started:", err)
	}

	scheduler.StartAsync()
	defer scheduler.Stop()

	h := router.CreateMinioidcRoutes(mux, m.config, m.Now)
	return h
}

// Config returns the Minioidc configuration.
func (m *Minioidc) Config() *domain.Config {
	return m.config
}

// CleanExpired removes expired sessions and grants from the stores.
func (m *Minioidc) CleanExpired() {
	m.config.SessionStore.CleanExpired()
	m.config.GrantStore.CleanExpired()
	log.Println("CleanExpired: Expired sessions and grants have been removed")
}

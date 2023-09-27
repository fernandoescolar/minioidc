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

func NewMinioidc(config *domain.Config) (*Minioidc, error) {
	return &Minioidc{
		Now:    time.Now,
		config: config,
	}, nil
}

func (m *Minioidc) Add(mux *http.ServeMux) {
	scheduler := gocron.NewScheduler(time.UTC)
	_, err := scheduler.Every(1).Hour().Do(m.CleanExpired)
	if err != nil {
		log.Println("Error scheduling CleanExpired job:", err)
	}

	scheduler.StartAsync()
	defer scheduler.Stop()

	router.CreateMinioidcRoutes(mux, m.config, m.Now)
}

func (m *Minioidc) Config() *domain.Config {
	return m.config
}

func (m *Minioidc) CleanExpired() {
	m.config.SessionStore.CleanExpired()
	m.config.GrantStore.CleanExpired()
	log.Println("CleanExpired: Expired sessions and grants have been removed")
}

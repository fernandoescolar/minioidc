package api

import (
	"log"
	"net/http"
	"time"

	"github.com/fernandoescolar/minioidc/api/router"
	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/go-co-op/gocron"
)

var NowFunc = time.Now

type Minioidc struct {
	Now    func() time.Time
	config *domain.Config
}

func NewMinioidc(config *domain.Config) (*Minioidc, error) {
	return &Minioidc{
		Now:    NowFunc,
		config: config,
	}, nil
}

func (m *Minioidc) Add(mux *http.ServeMux) {
	scheduler := gocron.NewScheduler(time.UTC)
	scheduler.Every(1).Hour().Do(m.CleanExpired)
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

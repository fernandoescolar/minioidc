package middlewares

import (
	"log"
	"net/http"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

type UpdateSessionTTL struct {
	now          func() time.Time
	ttl          time.Duration
	masterKey    string
	sessionStore domain.SessionStore
}

var _ domain.Middleware = (*UpdateSessionTTL)(nil)

func NewUpdateSessionTTL(config *domain.Config, now func() time.Time) *UpdateSessionTTL {
	return &UpdateSessionTTL{
		now:          now,
		ttl:          config.SessionTTL,
		masterKey:    config.MasterKey,
		sessionStore: config.SessionStore,
	}
}

func (m *UpdateSessionTTL) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	session := utils.GetSession(r)
	if session != nil {
		err := m.sessionStore.UpdateTTL(session.ID(), m.now().Add(m.ttl))
		if err != nil {
			// no matter is the session has been updated or not
			log.Printf("Failed to update session TTL: %v", err)
		}
	}

	next(w, r)
}

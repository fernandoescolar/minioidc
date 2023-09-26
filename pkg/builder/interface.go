package builder

import "github.com/fernandoescolar/minioidc/pkg/domain"

type IBuilder interface {
	Build() *domain.Config
}

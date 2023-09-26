package domain

import (
	"time"

	"github.com/fernandoescolar/minioidc/pkg/cryptography"
)

type Config struct {
	Issuer   string
	Audience string

	Keypair *cryptography.Keypair

	AccessTTL  time.Duration
	RefreshTTL time.Duration
	SessionTTL time.Duration
	CodeTTL    time.Duration

	ClientStore  ClientStore
	GrantStore   GrantStore
	SessionStore SessionStore
	UserStore    UserStore

	LoginTemplateFilepath string
}

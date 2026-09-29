package handlers

import (
	"errors"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/golang-jwt/jwt/v5"
)

// accessTokenValidator validates the access tokens issued by this server
type accessTokenValidator struct {
	now          func() time.Time
	issuer       string
	audience     string
	keypair      *cryptography.Keypair
	sessionStore domain.SessionStore
	clientStore  domain.ClientStore
}

func newAccessTokenValidator(config *domain.Config, now func() time.Time) *accessTokenValidator {
	return &accessTokenValidator{
		now:          now,
		issuer:       config.Issuer,
		audience:     config.Audience,
		keypair:      config.Keypair,
		sessionStore: config.SessionStore,
		clientStore:  config.ClientStore,
	}
}

// validate checks the signature, type, issuer, audience and expiration of the
// token. A user token is only valid while its session exists (logout revokes
// it). A client token (client_credentials) has no session: the returned
// session is nil, and it is valid while the client exists.
func (v *accessTokenValidator) validate(accessToken string) (*domain.AccessTokenClaims, domain.Session, error) {
	claims := &domain.AccessTokenClaims{}
	token, err := v.keypair.VerifyJWT(accessToken, claims,
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(v.now),
	)
	if err != nil {
		return nil, nil, err
	}

	if token.Header["typ"] != domain.AccessTokenType {
		return nil, nil, errors.New("it is not an access token")
	}

	if claims.SessionID == "" {
		if claims.Subject == "" || claims.Subject != claims.ClientID {
			return nil, nil, errors.New("invalid client token")
		}

		if _, err := v.clientStore.GetClientByID(claims.ClientID); err != nil {
			return nil, nil, errors.New("the client does not exist")
		}

		return claims, nil, nil
	}

	session, err := v.sessionStore.GetSessionByID(claims.SessionID)
	if err != nil || session.HasExpired(v.now()) || session.User().ID() != claims.Subject {
		return nil, nil, errors.New("the session has expired")
	}

	return claims, session, nil
}

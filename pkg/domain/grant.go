package domain

import (
	"time"

	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/golang-jwt/jwt"
)

type GrantStore interface {
	NewCodeGrant(id string, client Client, session Session, expiresAt time.Time, scopes []string, nonce string, codeChallenge, codeChallengeMethod string) (Grant, error)
	NewRefreshTokenGrant(id string, client Client, session Session, expiresAt time.Time, scopes []string) (Grant, error)
	GetGrantByToken(token *jwt.Token) (Grant, error)
	GetGrantByIDAndType(id string, grantType GrantType) (Grant, error)
	Grant(id string) error
	CleanExpired()
}

type GrantType string

const (
	GrantTypeCode    GrantType = "code"
	GrantTypeRefresh GrantType = "refresh"
)

type Grant interface {
	ID() string
	GrantType() GrantType
	User() User
	Scopes() []string
	HasBeenGranted() bool
	HasExpired() bool
	Session() Session
	Client() Client
	CodeChallenge() string
	CodeChallengeMethod() string
	AccessToken(issuer string, audience string, ttl time.Duration, kp *cryptography.Keypair, now time.Time) (string, error)
	RefreshToken(issuer string, audience string, ttl time.Duration, kp *cryptography.Keypair, now time.Time) (string, error)
	IDToken(issuer string, audience string, ttl time.Duration, kp *cryptography.Keypair, now time.Time) (string, error)
}

type grant struct {
	id                  string
	grantType           GrantType
	user                User
	session             Session
	client              Client
	granted             bool
	expiresAt           time.Time
	scopes              []string
	nonce               string
	codeChallenge       string
	codeChallengeMethod string
}

type standardClaims struct {
	Audience  []string `json:"aud,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	Id        string   `json:"jti,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	Issuer    string   `json:"iss,omitempty"`
	NotBefore int64    `json:"nbf,omitempty"`
	Subject   string   `json:"sub,omitempty"`
}

func (c standardClaims) Valid() error {
	return nil
}

// IDTokenClaims are the mandatory claims any User.Claims implementation
// should use in their jwt.Claims building.
type IDTokenClaims struct {
	Nonce string `json:"nonce,omitempty"`
	*standardClaims
}

func NewGrant(grantID string, grantType GrantType, client Client, session Session, expiresAt time.Time, scopes []string, oidcNonce, codeChallenge, codeChallengeMethod string) Grant {
	return Grant(&grant{
		id:                  grantID,
		grantType:           grantType,
		user:                session.User(),
		session:             session,
		client:              client,
		expiresAt:           expiresAt,
		scopes:              scopes,
		nonce:               oidcNonce,
		codeChallenge:       codeChallenge,
		codeChallengeMethod: codeChallengeMethod,
	})
}

func (g *grant) ID() string {
	return g.id
}

func (g *grant) GrantType() GrantType {
	return g.grantType
}

func (g *grant) User() User {
	return g.user
}

func (g *grant) Scopes() []string {
	return g.scopes
}

func (g *grant) HasBeenGranted() bool {
	return g.granted
}

func (g *grant) HasExpired() bool {
	return g.expiresAt.Before(time.Now())
}

func (g *grant) ExpiresAtUnix() int64 {
	return g.expiresAt.Unix()
}

func (g *grant) Session() Session {
	return g.session
}

func (g *grant) Client() Client {
	return g.client
}

func (g *grant) CodeChallenge() string {
	return g.codeChallenge
}

func (g *grant) CodeChallengeMethod() string {
	return g.codeChallengeMethod
}

func (g *grant) AccessToken(issuer string, audience string, ttl time.Duration, kp *cryptography.Keypair, now time.Time) (string, error) {
	clientTTL := g.client.GetAccessTokenTTL()
	if clientTTL != nil {
		ttl = *clientTTL
	}

	claims := g.standardClaims(issuer, audience, ttl, now)
	return kp.SignJWT(claims)
}

func (g *grant) RefreshToken(issuer string, audience string, ttl time.Duration, kp *cryptography.Keypair, now time.Time) (string, error) {
	clientTTL := g.client.GetRefreshTokenTTL()
	if clientTTL != nil {
		ttl = *clientTTL
	}

	claims := g.standardClaims(issuer, audience, ttl, now)
	return kp.SignJWT(claims)
}

func (g *grant) IDToken(issuer string, audience string, ttl time.Duration, kp *cryptography.Keypair, now time.Time) (string, error) {
	clientTTL := g.client.GetIDTokenTTL()
	if clientTTL != nil {
		ttl = *clientTTL
	}

	base := &IDTokenClaims{
		standardClaims: g.standardClaims(issuer, audience, ttl, now),
		Nonce:          g.nonce,
	}
	claims, err := g.user.Claims(g.scopes, base)
	if err != nil {
		return "", err
	}

	return kp.SignJWT(claims)
}

func (g *grant) standardClaims(issuer string, audience string, ttl time.Duration, now time.Time) *standardClaims {
	audiences := g.client.GetAudiences()
	if audience != "" {
		audiences = append(audiences, audience)
	}

	return &standardClaims{
		Audience:  audiences,
		ExpiresAt: now.Add(ttl).Unix(),
		Id:        g.ID(),
		IssuedAt:  now.Unix(),
		Issuer:    issuer,
		NotBefore: now.Unix(),
		Subject:   g.user.ID(),
	}
}

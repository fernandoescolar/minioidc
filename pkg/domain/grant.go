package domain

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AccessTokenType is the JWT "typ" header of access tokens (RFC 9068)
const AccessTokenType = "at+jwt"

type GrantStore interface {
	NewCodeGrant(id string, client Client, session Session, expiresAt time.Time, scopes []string, nonce string, codeChallenge, codeChallengeMethod, redirectURI string) (Grant, error)
	// NewRefreshTokenGrant creates a refresh token in the family of the grant it comes from
	NewRefreshTokenGrant(id, familyID string, client Client, session Session, expiresAt time.Time, scopes []string) (Grant, error)
	// GetGrantByIDAndType returns the grant, even if it has been used
	GetGrantByIDAndType(id string, grantType GrantType) (Grant, error)
	// Grant marks the grant as used so it cannot be used again. It fails if the
	// grant does not exist or it is already used, so two concurrent requests
	// cannot consume it twice. Used grants are kept to detect replays.
	Grant(id string) error
	// RevokeFamily deletes the grant and all the refresh tokens issued from it
	RevokeFamily(familyID string) error
	// RevokeClient deletes all the codes and refresh tokens of a client
	RevokeClient(clientID string) error
	CleanExpired()
}

type GrantType string

const (
	GrantTypeCode    GrantType = "code"
	GrantTypeRefresh GrantType = "refresh"
)

type Grant interface {
	ID() string
	// FamilyID is the ID of the authorization code the grant comes from
	FamilyID() string
	// Used is true if the grant has already been consumed
	Used() bool
	GrantType() GrantType
	User() User
	Scopes() []string
	HasScope(scope string) bool
	HasExpired(now time.Time) bool
	ExpiresAt() time.Time
	Session() Session
	Client() Client
	CodeChallenge() string
	CodeChallengeMethod() string
	// RedirectURI is the redirect_uri of the authorization request (code grants)
	RedirectURI() string
	AccessToken(issuer string, audience string, ttl time.Duration, kp *cryptography.Keypair, now time.Time) (string, error)
	IDToken(issuer string, ttl time.Duration, kp *cryptography.Keypair, now time.Time, accessToken string) (string, error)
}

type grant struct {
	id                  string
	familyID            string
	used                bool
	grantType           GrantType
	user                User
	session             Session
	client              Client
	expiresAt           time.Time
	scopes              []string
	nonce               string
	codeChallenge       string
	codeChallengeMethod string
	redirectURI         string
}

// AccessTokenClaims are the claims of the JWT access tokens
type AccessTokenClaims struct {
	jwt.RegisteredClaims
	ClientID  string `json:"client_id"`
	Scope     string `json:"scope,omitempty"`
	SessionID string `json:"sid,omitempty"`
}

// IDTokenClaims are the mandatory claims any User.Claims implementation
// should use in their jwt.Claims building.
type IDTokenClaims struct {
	jwt.RegisteredClaims
	Nonce           string   `json:"nonce,omitempty"`
	AuthTime        int64    `json:"auth_time,omitempty"`
	AuthorizedParty string   `json:"azp,omitempty"`
	AccessTokenHash string   `json:"at_hash,omitempty"`
	AuthMethods     []string `json:"amr,omitempty"`
	SessionID       string   `json:"sid,omitempty"`
}

// GrantData are the properties of a stored grant
type GrantData struct {
	ID                  string
	FamilyID            string
	Used                bool
	GrantType           GrantType
	ExpiresAt           time.Time
	Scopes              []string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	RedirectURI         string
}

func NewGrant(data GrantData, client Client, session Session) Grant {
	return Grant(&grant{
		id:                  data.ID,
		familyID:            data.FamilyID,
		used:                data.Used,
		grantType:           data.GrantType,
		user:                session.User(),
		session:             session,
		client:              client,
		expiresAt:           data.ExpiresAt,
		scopes:              data.Scopes,
		nonce:               data.Nonce,
		codeChallenge:       data.CodeChallenge,
		codeChallengeMethod: data.CodeChallengeMethod,
		redirectURI:         data.RedirectURI,
	})
}

func (g *grant) FamilyID() string {
	return g.familyID
}

func (g *grant) Used() bool {
	return g.used
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

func (g *grant) HasScope(scope string) bool {
	for _, s := range g.scopes {
		if s == scope {
			return true
		}
	}

	return false
}

func (g *grant) HasExpired(now time.Time) bool {
	return !now.Before(g.expiresAt)
}

func (g *grant) ExpiresAt() time.Time {
	return g.expiresAt
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

func (g *grant) RedirectURI() string {
	return g.redirectURI
}

func (g *grant) AccessToken(issuer string, audience string, ttl time.Duration, kp *cryptography.Keypair, now time.Time) (string, error) {
	claims := &AccessTokenClaims{
		RegisteredClaims: g.registeredClaims(issuer, audience, ttl, now),
		ClientID:         g.client.ClientID(),
		Scope:            strings.Join(g.scopes, " "),
		SessionID:        g.session.ID(),
	}

	return kp.SignJWT(claims, map[string]interface{}{"typ": AccessTokenType})
}

func (g *grant) IDToken(issuer string, ttl time.Duration, kp *cryptography.Keypair, now time.Time, accessToken string) (string, error) {
	clientID := g.client.ClientID()
	base := &IDTokenClaims{
		RegisteredClaims: g.registeredClaims(issuer, clientID, ttl, now),
		Nonce:            g.nonce,
		AuthTime:         g.session.AuthTime().Unix(),
		AuthorizedParty:  clientID,
		AccessTokenHash:  accessTokenHash(accessToken),
		AuthMethods:      g.session.AuthMethods(),
		SessionID:        g.session.ID(),
	}
	claims, err := g.user.Claims(g.scopes, base)
	if err != nil {
		return "", err
	}

	return kp.SignJWT(claims)
}

func (g *grant) registeredClaims(issuer string, audience string, ttl time.Duration, now time.Time) jwt.RegisteredClaims {
	return jwt.RegisteredClaims{
		Audience:  jwt.ClaimStrings{audience},
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		ID:        uuid.NewString(),
		IssuedAt:  jwt.NewNumericDate(now),
		Issuer:    issuer,
		NotBefore: jwt.NewNumericDate(now),
		Subject:   g.user.ID(),
	}
}

// accessTokenHash computes the at_hash claim for RS256 (OIDC Core 3.1.3.6)
func accessTokenHash(accessToken string) string {
	if accessToken == "" {
		return ""
	}

	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

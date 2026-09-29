// Package clientauth authenticates the clients at the token, revocation and
// introspection endpoints: client_secret_basic, client_secret_post,
// client_secret_jwt, private_key_jwt (RFC 7523, OIDC Core section 9) and none.
package clientauth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/golang-jwt/jwt/v5"
)

const (
	// AssertionType is the client_assertion_type of JWT assertions (RFC 7523 section 2.2)
	AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	// maxAssertionLifetime limits the exp of the assertions, so the used jti
	// do not have to be remembered for a long time
	maxAssertionLifetime = time.Hour
	clockSkew            = 30 * time.Second
)

var (
	// HMACAlgorithms are the algorithms of client_secret_jwt assertions
	HMACAlgorithms = []string{"HS256", "HS384", "HS512"}
	// AsymmetricAlgorithms are the algorithms of private_key_jwt assertions
	AsymmetricAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)

// Error is an authentication error with its OAuth error code
type Error struct {
	Code        string
	Description string
	// Basic is true when the client used HTTP Basic authentication, so the
	// response must include the WWW-Authenticate header
	Basic bool
}

func (e *Error) Error() string {
	return e.Code + ": " + e.Description
}

func invalidClient(description string, basic bool) *Error {
	return &Error{Code: "invalid_client", Description: description, Basic: basic}
}

func invalidRequest(description string) *Error {
	return &Error{Code: "invalid_request", Description: description}
}

// Authenticator authenticates the clients. It must be shared by all the
// endpoints, because it remembers the used assertions to prevent replays.
type Authenticator struct {
	clientStore domain.ClientStore
	now         func() time.Time
	audiences   []string
	assertions  domain.ClientAssertionStore
	keys        *jwksCache
}

// New creates an Authenticator. The assertions must have as audience the
// issuer, the token endpoint URL or the URL of the endpoint where they are used.
func New(clientStore domain.ClientStore, assertions domain.ClientAssertionStore, issuer, tokenEndpointURL string, now func() time.Time, httpClient *http.Client) *Authenticator {
	return &Authenticator{
		clientStore: clientStore,
		now:         now,
		audiences:   []string{issuer, strings.TrimSuffix(issuer, "/"), tokenEndpointURL},
		assertions:  assertions,
		keys:        newJWKSCache(httpClient, now),
	}
}

// Authenticate authenticates the client of a request with a parsed form. The
// endpointURL is the URL of the endpoint that receives the request.
func (a *Authenticator) Authenticate(r *http.Request, endpointURL string) (domain.Client, error) {
	id, secret, basic := r.BasicAuth()
	assertion := r.PostForm.Get("client_assertion")
	assertionType := r.PostForm.Get("client_assertion_type")
	formSecret := r.PostForm.Get("client_secret")

	// RFC 6749 section 2.3: the client must use only one authentication method
	methods := 0
	for _, used := range []bool{basic, formSecret != "", assertion != "" || assertionType != ""} {
		if used {
			methods++
		}
	}
	if methods > 1 {
		return nil, invalidRequest("Only one client authentication method can be used")
	}

	switch {
	case assertion != "" || assertionType != "":
		return a.authenticateAssertion(r, assertionType, assertion, endpointURL)
	case basic:
		return a.authenticateBasic(r, id, secret)
	case formSecret != "":
		return a.authenticateSecret(r.PostForm.Get("client_id"), formSecret, domain.AuthMethodClientSecretPost, false)
	default:
		client, err := a.getClient(r.PostForm.Get("client_id"), false)
		if err != nil {
			return nil, err
		}

		if !client.AuthMethodAllowed(domain.AuthMethodNone) {
			return nil, invalidClient("Client authentication failed", false)
		}

		return client, nil
	}
}

func (a *Authenticator) authenticateBasic(r *http.Request, id, secret string) (domain.Client, error) {
	// RFC 6749 section 2.3.1: credentials are form-urlencoded
	clientID, errID := url.QueryUnescape(id)
	clientSecret, errSecret := url.QueryUnescape(secret)
	if errID != nil || errSecret != nil {
		return nil, invalidClient("Client authentication failed", true)
	}

	if formID := r.PostForm.Get("client_id"); formID != "" && formID != clientID {
		return nil, invalidRequest("client_id does not match the authorization header")
	}

	return a.authenticateSecret(clientID, clientSecret, domain.AuthMethodClientSecretBasic, true)
}

func (a *Authenticator) authenticateSecret(clientID, secret, method string, basic bool) (domain.Client, error) {
	client, err := a.getClient(clientID, basic)
	if err != nil {
		return nil, err
	}

	if !client.AuthMethodAllowed(method) || !client.ClientSecretIsValid(secret) {
		return nil, invalidClient("Client authentication failed", basic)
	}

	return client, nil
}

func (a *Authenticator) getClient(clientID string, basic bool) (domain.Client, error) {
	if clientID == "" {
		return nil, invalidClient("Client authentication failed", basic)
	}

	client, err := a.clientStore.GetClientByID(clientID)
	if err != nil {
		return nil, invalidClient("Client authentication failed", basic)
	}

	return client, nil
}

func (a *Authenticator) authenticateAssertion(r *http.Request, assertionType, assertion, endpointURL string) (domain.Client, error) {
	if assertionType != AssertionType {
		return nil, invalidRequest("Unsupported client_assertion_type")
	}

	if assertion == "" {
		return nil, invalidRequest("The request is missing the required parameter: client_assertion")
	}

	// the client is the issuer of the assertion; the signature is verified below
	unverified := &jwt.RegisteredClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(assertion, unverified); err != nil {
		return nil, invalidClient("Invalid client assertion", false)
	}

	clientID := unverified.Issuer
	if formID := r.PostForm.Get("client_id"); formID != "" && formID != clientID {
		return nil, invalidClient("client_id does not match the client assertion", false)
	}

	client, err := a.getClient(clientID, false)
	if err != nil {
		return nil, err
	}

	var (
		keyFunc    jwt.Keyfunc
		algorithms []string
	)
	switch {
	case client.AuthMethodAllowed(domain.AuthMethodClientSecretJWT):
		keyFunc, algorithms = a.secretKey(client), HMACAlgorithms
	case client.AuthMethodAllowed(domain.AuthMethodPrivateKeyJWT):
		keyFunc, algorithms = a.publicKeys(client), AsymmetricAlgorithms
	default:
		return nil, invalidClient("Client authentication failed", false)
	}

	if _, err := a.verify(assertion, client.ClientID(), true, keyFunc, algorithms, endpointURL, "client"); err != nil {
		return nil, invalidClient(err.Error(), false)
	}

	return client, nil
}

// VerifyGrantAssertion verifies a JWT bearer authorization grant (RFC 7523
// section 2.1): an assertion signed by the client with its registered keys
// (or its client_secret_jwt secret) about a user (the sub claim). It returns
// the claims of the assertion.
func (a *Authenticator) VerifyGrantAssertion(client domain.Client, assertion, endpointURL string) (*jwt.RegisteredClaims, error) {
	data := client.Data()
	var (
		keyFunc    jwt.Keyfunc
		algorithms []string
	)
	switch {
	case data.JWKSURI != "" || len(data.PublicKeys) > 0:
		keyFunc, algorithms = a.publicKeys(client), AsymmetricAlgorithms
	case data.Secret != "":
		keyFunc, algorithms = a.secretKey(client), HMACAlgorithms
	default:
		return nil, errors.New("the client has no keys to verify assertions")
	}

	return a.verify(assertion, client.ClientID(), false, keyFunc, algorithms, endpointURL, "grant")
}

// verify checks an assertion issued by the client: signature, iss, aud, exp,
// iat and a jti that can only be used once. When subjectIsClient is true, the
// sub must be the client (client authentication), otherwise it is required.
func (a *Authenticator) verify(assertion, clientID string, subjectIsClient bool, keyFunc jwt.Keyfunc, algorithms []string, endpointURL, kind string) (*jwt.RegisteredClaims, error) {
	options := []jwt.ParserOption{
		jwt.WithValidMethods(algorithms),
		jwt.WithIssuer(clientID),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(clockSkew),
		jwt.WithTimeFunc(a.now),
	}
	if subjectIsClient {
		options = append(options, jwt.WithSubject(clientID))
	}

	claims := &jwt.RegisteredClaims{}
	if _, err := jwt.ParseWithClaims(assertion, claims, keyFunc, options...); err != nil {
		return nil, fmt.Errorf("Invalid %s assertion: %w", kind, err)
	}

	switch {
	case claims.Subject == "":
		return nil, fmt.Errorf("The %s assertion must have a sub", kind)
	case !a.validAudience(claims.Audience, endpointURL):
		return nil, fmt.Errorf("Invalid %s assertion audience", kind)
	case claims.ID == "":
		return nil, fmt.Errorf("The %s assertion must have a jti", kind)
	case claims.ExpiresAt.Sub(a.now()) > maxAssertionLifetime:
		return nil, fmt.Errorf("The %s assertion expiration is too far", kind)
	}

	// RFC 7523 section 3: the jti can only be used once
	unused, err := a.assertions.Use(kind+":"+clientID+":"+claims.ID, claims.ExpiresAt.Add(clockSkew), a.now())
	if err != nil {
		return nil, err
	}

	if !unused {
		return nil, fmt.Errorf("The %s assertion has already been used", kind)
	}

	return claims, nil
}

func (a *Authenticator) secretKey(client domain.Client) jwt.Keyfunc {
	secret := []byte(client.Data().Secret)
	return func(*jwt.Token) (interface{}, error) { return secret, nil }
}

func (a *Authenticator) validAudience(audience jwt.ClaimStrings, endpointURL string) bool {
	for _, aud := range audience {
		if aud == endpointURL {
			return true
		}

		for _, valid := range a.audiences {
			if aud == valid {
				return true
			}
		}
	}

	return false
}

// publicKeys returns the keys of a private_key_jwt client that can verify the assertion
func (a *Authenticator) publicKeys(client domain.Client) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		data := client.Data()
		keys := jwt.VerificationKeySet{}
		for _, key := range data.PublicKeys {
			keys.Keys = append(keys.Keys, key)
		}

		if data.JWKSURI != "" {
			kid, _ := token.Header["kid"].(string)
			jwks, err := a.keys.Get(data.JWKSURI, kid)
			if err != nil {
				return nil, err
			}

			for _, jwk := range jwks {
				if kid == "" || jwk.KeyID == "" || jwk.KeyID == kid {
					keys.Keys = append(keys.Keys, jwk.Key)
				}
			}
		}

		if len(keys.Keys) == 0 {
			return nil, errors.New("no key found for the client assertion")
		}

		return keys, nil
	}
}

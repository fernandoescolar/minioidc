package api_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/api"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	resourceServerID     = "resource-server"
	privateKeyClientID   = "private-key-client"
	resourceServerSecret = "resource-server-secret"
)

type introspection struct {
	Active    bool   `json:"active"`
	ClientID  string `json:"client_id"`
	Subject   string `json:"sub"`
	Scope     string `json:"scope"`
	TokenType string `json:"token_type"`
	Username  string `json:"username"`
}

func newClientAuthServer(t *testing.T, options ...func(*api.Builder)) (*testServer, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	return newClientAuthServerWithKey(t, key, options...), key
}

func newClientAuthServerWithKey(t *testing.T, key *rsa.PrivateKey, options ...func(*api.Builder)) *testServer {
	t.Helper()
	options = append([]func(*api.Builder){func(b *api.Builder) {
		b.Clients = append(b.Clients,
			// a resource server: it only introspects tokens
			api.Client{ID: resourceServerID, SecretHash: hash(t, resourceServerSecret)},
			api.Client{ID: privateKeyClientID, RedirectURIs: []string{redirectURI}, TokenEndpointAuthMethod: "private_key_jwt", PublicKeys: []crypto.PublicKey{&key.PublicKey}},
		)
	}}, options...)

	return newTestServer(t, false, options...)
}

func clientAssertion(t *testing.T, key *rsa.PrivateKey, audience string) string {
	t.Helper()
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": privateKeyClientID, "sub": privateKeyClientID, "aud": audience,
		"jti": uuid.NewString(), "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	})

	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

	return signed
}

func withAssertion(form url.Values, assertion string) url.Values {
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	return form
}

func (s *testServer) introspect(t *testing.T, token string, auth func(url.Values) (url.Values, func(*http.Request))) (*http.Response, introspection) {
	t.Helper()
	form, setup := auth(url.Values{"token": {token}})
	var setups []func(*http.Request)
	if setup != nil {
		setups = append(setups, setup)
	}

	resp, body := postForm(t, http.DefaultClient, s.url("/connect/introspect"), form, setups...)
	var result introspection
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal([]byte(body), &result); err != nil {
			t.Fatal(err)
		}
	}

	return resp, result
}

func asResourceServer(form url.Values) (url.Values, func(*http.Request)) {
	return form, basicAuth(resourceServerID, resourceServerSecret)
}

func TestPrivateKeyJWTClient(t *testing.T) {
	s, key := newClientAuthServer(t)
	code := s.authorize(t, browser(t), authorizePath(privateKeyClientID, nil))

	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {codeVerifier}}

	// the client cannot authenticate with a method it has not registered
	resp, body := postForm(t, http.DefaultClient, s.url("/connect/token"), url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {codeVerifier}, "client_id": {privateKeyClientID},
	})
	expectError(t, resp, body, http.StatusUnauthorized, "invalid_client")

	resp, body = postForm(t, http.DefaultClient, s.url("/connect/token"), withAssertion(form, clientAssertion(t, key, "http://issuer.test/connect/token")))
	expectStatus(t, resp, body, http.StatusOK)
	var tk tokens
	_ = json.Unmarshal([]byte(body), &tk)

	// the refresh token can be introspected by its client, with an assertion for the introspection endpoint
	resp, result := s.introspect(t, tk.RefreshToken, func(f url.Values) (url.Values, func(*http.Request)) {
		return withAssertion(f, clientAssertion(t, key, "http://issuer.test/connect/introspect")), nil
	})
	expectStatus(t, resp, "", http.StatusOK)
	if !result.Active || result.TokenType != "refresh_token" || result.ClientID != privateKeyClientID {
		t.Errorf("Expected an active refresh token: %+v", result)
	}

	// but not by other clients
	_, result = s.introspect(t, tk.RefreshToken, asResourceServer)
	if result.Active {
		t.Error("Expected the refresh token to be inactive for other clients")
	}
}

func TestIntrospection(t *testing.T) {
	s, _ := newClientAuthServer(t)
	c := browser(t)
	tk := s.exchangeCode(t, s.authorize(t, c, authorizePath(clientID, nil)))

	resp, result := s.introspect(t, tk.AccessToken, asResourceServer)
	expectStatus(t, resp, "", http.StatusOK)
	if !result.Active || result.ClientID != clientID || result.Subject != "1" || result.TokenType != "Bearer" ||
		result.Username != "user@mail.test" || !strings.Contains(result.Scope, "openid") {
		t.Errorf("Unexpected introspection: %+v", result)
	}

	// the hint only changes the order
	_, result = s.introspect(t, tk.AccessToken, func(f url.Values) (url.Values, func(*http.Request)) {
		f.Set("token_type_hint", "refresh_token")
		return asResourceServer(f)
	})
	if !result.Active {
		t.Error("Expected the access token to be active with a wrong hint")
	}

	for _, token := range []string{"garbage", tk.IDToken, tk.AccessToken + "x"} {
		_, result = s.introspect(t, token, asResourceServer)
		if result.Active {
			t.Errorf("Expected %s to be inactive", token)
		}
	}

	// the refresh token is active for its client until it is rotated
	_, result = s.introspect(t, tk.RefreshToken, func(f url.Values) (url.Values, func(*http.Request)) {
		return f, basicAuth(clientID, clientSecret)
	})
	if !result.Active {
		t.Error("Expected an active refresh token")
	}

	resp, body := s.refresh(http.DefaultClient, t, tk.RefreshToken)
	expectStatus(t, resp, body, http.StatusOK)
	_, result = s.introspect(t, tk.RefreshToken, func(f url.Values) (url.Values, func(*http.Request)) {
		return f, basicAuth(clientID, clientSecret)
	})
	if result.Active {
		t.Error("Expected a rotated refresh token to be inactive")
	}

	// public clients and unauthenticated requests cannot introspect
	resp, _ = s.introspect(t, tk.AccessToken, func(f url.Values) (url.Values, func(*http.Request)) {
		f.Set("client_id", publicClientID)
		return f, nil
	})
	expectStatus(t, resp, "", http.StatusUnauthorized)

	resp, _ = s.introspect(t, tk.AccessToken, func(f url.Values) (url.Values, func(*http.Request)) { return f, nil })
	expectStatus(t, resp, "", http.StatusUnauthorized)

	// the access token is inactive after the logout
	logout := url.Values{"id_token_hint": {tk.IDToken}}
	resp, _ = get(t, c, s.url("/connect/endsession?"+logout.Encode()))
	expectStatus(t, resp, "", http.StatusOK)
	_, result = s.introspect(t, tk.AccessToken, asResourceServer)
	if result.Active {
		t.Error("Expected the access token to be inactive after the logout")
	}
}

func TestClientAuthenticationDiscovery(t *testing.T) {
	s, _ := newClientAuthServer(t)
	resp, body := get(t, http.DefaultClient, s.url("/.well-known/openid-configuration"))
	expectStatus(t, resp, body, http.StatusOK)

	for _, expected := range []string{
		`"introspection_endpoint":"http://issuer.test/connect/introspect"`,
		`"private_key_jwt"`, `"client_secret_jwt"`,
		`"token_endpoint_auth_signing_alg_values_supported":["RS256"`,
		`"introspection_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt"]`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("Expected %s in discovery: %s", expected, body)
		}
	}
}

func TestInvalidClientConfiguration(t *testing.T) {
	for name, client := range map[string]api.Client{
		"short HMAC secret":       {ID: "c", Secret: "short", TokenEndpointAuthMethod: "client_secret_jwt"},
		"private key without key": {ID: "c", TokenEndpointAuthMethod: "private_key_jwt"},
		"unknown method":          {ID: "c", TokenEndpointAuthMethod: "tls_client_auth"},
		"public with secret":      {ID: "c", SecretHash: "x", TokenEndpointAuthMethod: "none"},
		"secret without method":   {ID: "c", Secret: strings.Repeat("s", 40)},
	} {
		b := &api.Builder{Issuer: issuer, Audience: audience, Clients: []api.Client{client}}
		if _, err := b.Build(); err == nil {
			t.Errorf("%s: expected a configuration error", name)
		}
	}
}

// Two instances sharing the SQLite database: an assertion used in one of them
// cannot be replayed in the other one
func TestClientAssertionReplayBetweenInstances(t *testing.T) {
	database := t.TempDir() + "/shared.sqlite3"
	useSQLite := func(b *api.Builder) { b.UseSQLite(database, api.ClientAssertions) }

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	first := newClientAuthServerWithKey(t, key, useSQLite)
	second := newClientAuthServerWithKey(t, key, useSQLite)

	assertion := clientAssertion(t, key, "http://issuer.test/connect/introspect")
	introspect := func(s *testServer) *http.Response {
		resp, _ := s.introspect(t, "any-token", func(f url.Values) (url.Values, func(*http.Request)) {
			return withAssertion(f, assertion), nil
		})
		return resp
	}

	expectStatus(t, introspect(first), "", http.StatusOK)
	expectStatus(t, introspect(second), "", http.StatusUnauthorized)
}

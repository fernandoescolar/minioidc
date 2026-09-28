package clientauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fernandoescolar/minioidc/internal/stores"
	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	issuer        = "https://issuer.test/"
	tokenEndpoint = "https://issuer.test/token"
	introspection = "https://issuer.test/introspect"
	hmacSecret    = "0123456789abcdefghijklmnopqrstuvwxyz"
)

type fixture struct {
	auth   *Authenticator
	now    time.Time
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
}

func newFixture(t *testing.T, jwksURI string) *fixture {
	t.Helper()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)

	store := stores.NewClientStore()
	for _, data := range []domain.ClientData{
		{ID: "basic", SecretHash: string(hash)},
		{ID: "public"},
		{ID: "hmac", Secret: hmacSecret, TokenEndpointAuthMethod: domain.AuthMethodClientSecretJWT},
		{ID: "keys", PublicKeys: []crypto.PublicKey{&rsaKey.PublicKey, &ecKey.PublicKey}, TokenEndpointAuthMethod: domain.AuthMethodPrivateKeyJWT},
		{ID: "only-post", SecretHash: string(hash), TokenEndpointAuthMethod: domain.AuthMethodClientSecretPost},
	} {
		if _, err := store.NewClient(data); err != nil {
			t.Fatal(err)
		}
	}

	if jwksURI != "" {
		if _, err := store.NewClient(domain.ClientData{ID: "remote", JWKSURI: jwksURI, TokenEndpointAuthMethod: domain.AuthMethodPrivateKeyJWT}); err != nil {
			t.Fatal(err)
		}
	}

	f := &fixture{now: time.Now(), rsaKey: rsaKey, ecKey: ecKey}
	f.auth = New(store, stores.NewClientAssertionStore(), issuer, tokenEndpoint, func() time.Time { return f.now }, http.DefaultClient)
	return f
}

func (f *fixture) claims(clientID string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": tokenEndpoint,
		"jti": randomID(),
		"iat": f.now.Unix(),
		"exp": f.now.Add(time.Minute).Unix(),
	}
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sign(t *testing.T, method jwt.SigningMethod, key interface{}, claims jwt.MapClaims, kid string) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}

	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

	return signed
}

func request(form url.Values, setup ...func(*http.Request)) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, s := range setup {
		s(r)
	}
	_ = r.ParseForm()
	return r
}

func assertionForm(assertion string) url.Values {
	return url.Values{"client_assertion_type": {AssertionType}, "client_assertion": {assertion}}
}

func expectClient(t *testing.T, client domain.Client, err error, id string) {
	t.Helper()
	if err != nil || client == nil || client.ClientID() != id {
		t.Fatalf("Expected client %s, got %v", id, err)
	}
}

func expectError(t *testing.T, err error, code string) {
	t.Helper()
	var authErr *Error
	if !errors.As(err, &authErr) || authErr.Code != code {
		t.Fatalf("Expected error %s, got %v", code, err)
	}
}

func TestSecretMethods(t *testing.T) {
	f := newFixture(t, "")

	client, err := f.auth.Authenticate(request(nil, func(r *http.Request) { r.SetBasicAuth("basic", "secret") }), tokenEndpoint)
	expectClient(t, client, err, "basic")

	client, err = f.auth.Authenticate(request(url.Values{"client_id": {"basic"}, "client_secret": {"secret"}}), tokenEndpoint)
	expectClient(t, client, err, "basic")

	_, err = f.auth.Authenticate(request(url.Values{"client_id": {"basic"}, "client_secret": {"wrong"}}), tokenEndpoint)
	expectError(t, err, "invalid_client")

	// a confidential client cannot authenticate as public
	_, err = f.auth.Authenticate(request(url.Values{"client_id": {"basic"}}), tokenEndpoint)
	expectError(t, err, "invalid_client")

	client, err = f.auth.Authenticate(request(url.Values{"client_id": {"public"}}), tokenEndpoint)
	expectClient(t, client, err, "public")

	// the registered method is the only one allowed
	_, err = f.auth.Authenticate(request(nil, func(r *http.Request) { r.SetBasicAuth("only-post", "secret") }), tokenEndpoint)
	expectError(t, err, "invalid_client")

	// only one method can be used
	_, err = f.auth.Authenticate(request(url.Values{"client_secret": {"secret"}}, func(r *http.Request) { r.SetBasicAuth("basic", "secret") }), tokenEndpoint)
	expectError(t, err, "invalid_request")
}

func TestPrivateKeyJWT(t *testing.T) {
	f := newFixture(t, "")

	claims := f.claims("keys")
	assertion := sign(t, jwt.SigningMethodRS256, f.rsaKey, claims, "")
	client, err := f.auth.Authenticate(request(assertionForm(assertion)), tokenEndpoint)
	expectClient(t, client, err, "keys")

	// the jti can only be used once
	_, err = f.auth.Authenticate(request(assertionForm(assertion)), tokenEndpoint)
	expectError(t, err, "invalid_client")

	client, err = f.auth.Authenticate(request(assertionForm(sign(t, jwt.SigningMethodES256, f.ecKey, f.claims("keys"), ""))), tokenEndpoint)
	expectClient(t, client, err, "keys")

	// the issuer and the URL of the endpoint are valid audiences too
	for _, aud := range []string{issuer, strings.TrimSuffix(issuer, "/"), introspection} {
		claims := f.claims("keys")
		claims["aud"] = aud
		client, err = f.auth.Authenticate(request(assertionForm(sign(t, jwt.SigningMethodPS256, f.rsaKey, claims, ""))), introspection)
		expectClient(t, client, err, "keys")
	}
}

func TestInvalidPrivateKeyJWT(t *testing.T) {
	f := newFixture(t, "")
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicDER, _ := x509.MarshalPKIXPublicKey(&f.rsaKey.PublicKey)

	cases := map[string]func() (url.Values, string){
		"wrong key": func() (url.Values, string) {
			return assertionForm(sign(t, jwt.SigningMethodRS256, otherKey, f.claims("keys"), "")), "invalid_client"
		},
		"wrong audience": func() (url.Values, string) {
			c := f.claims("keys")
			c["aud"] = "https://other.test/token"
			return assertionForm(sign(t, jwt.SigningMethodRS256, f.rsaKey, c, "")), "invalid_client"
		},
		"expired": func() (url.Values, string) {
			c := f.claims("keys")
			c["exp"] = f.now.Add(-time.Minute).Unix()
			return assertionForm(sign(t, jwt.SigningMethodRS256, f.rsaKey, c, "")), "invalid_client"
		},
		"without exp": func() (url.Values, string) {
			c := f.claims("keys")
			delete(c, "exp")
			return assertionForm(sign(t, jwt.SigningMethodRS256, f.rsaKey, c, "")), "invalid_client"
		},
		"exp too far": func() (url.Values, string) {
			c := f.claims("keys")
			c["exp"] = f.now.Add(2 * time.Hour).Unix()
			return assertionForm(sign(t, jwt.SigningMethodRS256, f.rsaKey, c, "")), "invalid_client"
		},
		"without jti": func() (url.Values, string) {
			c := f.claims("keys")
			delete(c, "jti")
			return assertionForm(sign(t, jwt.SigningMethodRS256, f.rsaKey, c, "")), "invalid_client"
		},
		"sub is not the client": func() (url.Values, string) {
			c := f.claims("keys")
			c["sub"] = "someone"
			return assertionForm(sign(t, jwt.SigningMethodRS256, f.rsaKey, c, "")), "invalid_client"
		},
		"client_id does not match": func() (url.Values, string) {
			form := assertionForm(sign(t, jwt.SigningMethodRS256, f.rsaKey, f.claims("keys"), ""))
			form.Set("client_id", "basic")
			return form, "invalid_client"
		},
		// algorithm confusion: HMAC signed with the public key
		"HMAC with the public key": func() (url.Values, string) {
			return assertionForm(sign(t, jwt.SigningMethodHS256, publicDER, f.claims("keys"), "")), "invalid_client"
		},
		"none algorithm": func() (url.Values, string) {
			return assertionForm(sign(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, f.claims("keys"), "")), "invalid_client"
		},
		"unsupported assertion type": func() (url.Values, string) {
			form := assertionForm(sign(t, jwt.SigningMethodRS256, f.rsaKey, f.claims("keys"), ""))
			form.Set("client_assertion_type", "urn:other")
			return form, "invalid_request"
		},
		// a client registered with private_key_jwt cannot use its secret
		"secret client with assertion": func() (url.Values, string) {
			return assertionForm(sign(t, jwt.SigningMethodRS256, f.rsaKey, f.claims("basic"), "")), "invalid_client"
		},
	}

	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			form, code := build()
			_, err := f.auth.Authenticate(request(form), tokenEndpoint)
			expectError(t, err, code)
		})
	}
}

func TestClientSecretJWT(t *testing.T) {
	f := newFixture(t, "")

	for _, method := range []jwt.SigningMethod{jwt.SigningMethodHS256, jwt.SigningMethodHS512} {
		client, err := f.auth.Authenticate(request(assertionForm(sign(t, method, []byte(hmacSecret), f.claims("hmac"), ""))), tokenEndpoint)
		expectClient(t, client, err, "hmac")
	}

	_, err := f.auth.Authenticate(request(assertionForm(sign(t, jwt.SigningMethodHS256, []byte("another secret another secret 123"), f.claims("hmac"), ""))), tokenEndpoint)
	expectError(t, err, "invalid_client")

	_, err = f.auth.Authenticate(request(assertionForm(sign(t, jwt.SigningMethodRS256, f.rsaKey, f.claims("hmac"), ""))), tokenEndpoint)
	expectError(t, err, "invalid_client")

	// the plain secret cannot be used with client_secret_post
	_, err = f.auth.Authenticate(request(url.Values{"client_id": {"hmac"}, "client_secret": {hmacSecret}}), tokenEndpoint)
	expectError(t, err, "invalid_client")
}

func jwksJSON(keys map[string]*rsa.PublicKey) []byte {
	set := struct {
		Keys []map[string]string `json:"keys"`
	}{}
	for kid, key := range keys {
		set.Keys = append(set.Keys, map[string]string{
			"kty": "RSA", "use": "sig", "kid": kid,
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		})
	}

	data, _ := json.Marshal(set)
	return data
}

func TestPrivateKeyJWTWithJWKSURI(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)

	var published atomic.Value
	published.Store(jwksJSON(map[string]*rsa.PublicKey{"key1": &key1.PublicKey}))
	var downloads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		downloads.Add(1)
		_, _ = w.Write(published.Load().([]byte))
	}))
	defer server.Close()

	f := newFixture(t, server.URL)
	client, err := f.auth.Authenticate(request(assertionForm(sign(t, jwt.SigningMethodRS256, key1, f.claims("remote"), "key1"))), tokenEndpoint)
	expectClient(t, client, err, "remote")

	// cached
	client, err = f.auth.Authenticate(request(assertionForm(sign(t, jwt.SigningMethodRS256, key1, f.claims("remote"), "key1"))), tokenEndpoint)
	expectClient(t, client, err, "remote")
	if downloads.Load() != 1 {
		t.Fatalf("Expected the JWKS to be cached, downloaded %d times", downloads.Load())
	}

	// the client rotates its key: the unknown kid downloads the JWKS again
	published.Store(jwksJSON(map[string]*rsa.PublicKey{"key2": &key2.PublicKey}))
	f.now = f.now.Add(2 * time.Minute)
	client, err = f.auth.Authenticate(request(assertionForm(sign(t, jwt.SigningMethodRS256, key2, f.claims("remote"), "key2"))), tokenEndpoint)
	expectClient(t, client, err, "remote")
	if downloads.Load() != 2 {
		t.Fatalf("Expected the JWKS to be downloaded again, downloaded %d times", downloads.Load())
	}

	// unknown keys do not download the JWKS more than once per minute
	for i := 0; i < 3; i++ {
		_, err = f.auth.Authenticate(request(assertionForm(sign(t, jwt.SigningMethodRS256, key1, f.claims("remote"), "unknown"))), tokenEndpoint)
		expectError(t, err, "invalid_client")
	}
	if downloads.Load() != 2 {
		t.Fatalf("Expected the JWKS downloads to be limited, downloaded %d times", downloads.Load())
	}
}

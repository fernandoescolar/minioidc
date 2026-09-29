package integration

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/fernandoescolar/minioidc/pkg/api"
)

const fakeIssuer = "https://auth.example.com"

var (
	testClient *Client
	// testClientKey signs the jwt-bearer assertions of myclient
	testClientKey *rsa.PrivateKey
)

// the grant types of the test clients: the suite exercises all of them
var allGrantTypes = []string{
	"authorization_code", "refresh_token", "client_credentials", "password",
	"urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:jwt-bearer", "implicit",
}

func TestMain(m *testing.M) {
	workspacefolder := os.Getenv("WORKSPACE_FOLDER")
	if workspacefolder != "" {
		if err := os.Chdir(workspacefolder); err != nil {
			log.Fatal(err)
		}
	} else {
		// Navigate to the project root relative to this test file's location.
		// This file is at tests/integration/, so the project root is two levels up.
		_, testFilePath, _, _ := runtime.Caller(0)
		projectRoot := filepath.Join(filepath.Dir(testFilePath), "../..")
		if err := os.Chdir(projectRoot); err != nil {
			log.Fatal(err)
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	testClientKey = key

	builder := &api.Builder{
		Issuer:   fakeIssuer,
		Audience: "https://api.example.com",
		// the discouraged flows are disabled by default: the suite tests them
		AllowImplicitFlow:  true,
		AllowPasswordGrant: true,
		Clients: []api.Client{
			{
				ID:                     "myclient",
				SecretHash:             "$2a$06$L6/zALdtbkYajjHTZUW29ePBEb/hwhgjhXC4YpHANavvKDJl69ctK", // secret
				RedirectURIs:           []string{"http://localhost/callback"},
				PostLogoutRedirectURIs: []string{"http://localhost/logged-out"},
				GrantTypes:             allGrantTypes,
				PublicKeys:             []crypto.PublicKey{&key.PublicKey},
			},
			{
				ID:           "publicclient",
				SecretHash:   "",
				RedirectURIs: []string{"http://localhost/callback"},
				GrantTypes:   []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code", "implicit"},
			},
		},
		Users: []api.User{
			{
				Subject:           "0000001",
				PreferredUsername: "user",
				Email:             "user@example.com",
				EmailVerified:     true,
				PasswordHash:      "$2a$06$03dduqc0lMbsb5go/l6RI.cRb03Hos9CMpgm5/yYuRsSQPHtrFwSq", // password
			},
			{
				// changes its password in the profile tests
				Subject:           "0000002",
				PreferredUsername: "pwuser",
				PasswordHash:      "$2a$06$03dduqc0lMbsb5go/l6RI.cRb03Hos9CMpgm5/yYuRsSQPHtrFwSq", // password
			},
		},
	}

	minioidc, err := builder.Build()
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	handler := minioidc.Wrap(mux)

	testServer := httptest.NewServer(handler)
	defer testServer.Close()

	testClient = initializeClient(testServer.URL)

	m.Run()
}

func initializeClient(url string) *Client {
	client := NewClient(url)
	req := client.NewRequest("GET", "/.well-known/openid-configuration")
	res, err := req.Send()
	if err != nil {
		log.Fatal(err)
	}

	defer res.Close()

	if res.StatusCode() != http.StatusOK {
		log.Fatalf("expected status %d, got %d", http.StatusOK, res.StatusCode())
	}

	discovery := DiscoveryResponse{}
	err = res.BodyAsJSON(&discovery)
	if err != nil {
		log.Fatal(err)
	}

	client.Discovery = discoveryEndpointsToRelative(fakeIssuer, discovery)
	return client
}

func discoveryEndpointsToRelative(baseUrl string, discovery DiscoveryResponse) DiscoveryResponse {
	discovery.JwksURI = removeBaseURL(baseUrl, discovery.JwksURI)
	discovery.AuthorizationEndpoint = removeBaseURL(baseUrl, discovery.AuthorizationEndpoint)
	discovery.TokenEndpoint = removeBaseURL(baseUrl, discovery.TokenEndpoint)
	discovery.UserinfoEndpoint = removeBaseURL(baseUrl, discovery.UserinfoEndpoint)
	discovery.IntrospectionEndpoint = removeBaseURL(baseUrl, discovery.IntrospectionEndpoint)
	discovery.RevocationEndpoint = removeBaseURL(baseUrl, discovery.RevocationEndpoint)
	discovery.EndSessionEndpoint = removeBaseURL(baseUrl, discovery.EndSessionEndpoint)
	discovery.CheckSessionIframe = removeBaseURL(baseUrl, discovery.CheckSessionIframe)
	discovery.RegistrationEndpoint = removeBaseURL(baseUrl, discovery.RegistrationEndpoint)
	discovery.DeviceAuthorizationEndpoint = removeBaseURL(baseUrl, discovery.DeviceAuthorizationEndpoint)

	return discovery
}

func removeBaseURL(baseUrl string, url string) string {
	baseUrl = strings.TrimRight(baseUrl, "/")
	if strings.HasPrefix(url, baseUrl) {

		return url[len(baseUrl):]
	}

	return url
}

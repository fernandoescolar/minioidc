package integration

import (
	"net/http"
	"testing"
)

func Test_JWTBearer_AdvertisedInDiscovery(t *testing.T) {
	found := false
	for _, gt := range testClient.Discovery.GrantTypesSupported {
		if gt == "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected urn:ietf:params:oauth:grant-type:jwt-bearer in grant_types_supported")
	}
}

// getAccessTokenViaPassword is a helper that performs a password grant and
// returns the raw access token string.
func getAccessTokenViaPassword(t *testing.T, scope string) string {
	t.Helper()
	testClient.Reset()
	req := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	req.SetBasicAuth("myclient", "secret")
	req.AddForm("grant_type", "password")
	req.AddForm("username", "user")
	req.AddForm("password", "password")
	if scope != "" {
		req.AddForm("scope", scope)
	}
	resp, err := req.Send()
	if err != nil {
		t.Fatalf("password grant error: %v", err)
	}
	defer resp.Close()
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("password grant expected 200, got %d", resp.StatusCode())
	}
	tokens := &TokenResponse{}
	if err := resp.BodyAsJSON(tokens); err != nil {
		t.Fatalf("parse password grant response: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Fatal("password grant returned empty access_token")
	}
	return tokens.AccessToken
}

func Test_JWTBearer_ValidAssertion(t *testing.T) {
	accessToken := getAccessTokenViaPassword(t, "")

	testClient.Reset()
	req := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	req.AddForm("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	req.AddForm("client_id", "myclient")
	req.AddForm("assertion", accessToken)

	resp, err := req.Send()
	if err != nil {
		t.Fatalf("jwt-bearer grant error: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode(), resp.BodyAsString())
	}

	tokens := &TokenResponse{}
	if err := resp.BodyAsJSON(tokens); err != nil {
		t.Fatalf("parse jwt-bearer response: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Fatal("expected access_token in jwt-bearer response")
	}
	if tokens.TokenType != "bearer" {
		t.Fatalf("expected token_type 'bearer', got %q", tokens.TokenType)
	}
}

func Test_JWTBearer_WithOpenIDScope(t *testing.T) {
	accessToken := getAccessTokenViaPassword(t, "openid")

	testClient.Reset()
	req := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	req.AddForm("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	req.AddForm("client_id", "myclient")
	req.AddForm("assertion", accessToken)
	req.AddForm("scope", "openid")

	resp, err := req.Send()
	if err != nil {
		t.Fatalf("jwt-bearer openid error: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode(), resp.BodyAsString())
	}

	tokens := &TokenResponse{}
	if err := resp.BodyAsJSON(tokens); err != nil {
		t.Fatalf("parse jwt-bearer openid response: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Fatal("expected access_token")
	}
	if tokens.IDToken == nil {
		t.Fatal("expected id_token with openid scope")
	}
}

func Test_JWTBearer_InvalidAssertion(t *testing.T) {
	testClient.Reset()
	req := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	req.AddForm("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	req.AddForm("client_id", "myclient")
	req.AddForm("assertion", "not-a-valid-jwt")

	resp, err := req.Send()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode() != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode())
	}
}

func Test_JWTBearer_MissingAssertion(t *testing.T) {
	testClient.Reset()
	req := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	req.AddForm("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	req.AddForm("client_id", "myclient")
	// No assertion field

	resp, err := req.Send()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode() != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode())
	}
}

func Test_JWTBearer_InvalidClient(t *testing.T) {
	accessToken := getAccessTokenViaPassword(t, "")

	testClient.Reset()
	req := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	req.AddForm("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	req.AddForm("client_id", "nonexistentclient")
	req.AddForm("assertion", accessToken)

	resp, err := req.Send()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode() != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode())
	}
}

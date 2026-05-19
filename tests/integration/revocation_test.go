package integration

import (
	"net/http"
	"testing"
)

// Test_Revocation_AdvertisedInDiscovery verifies the revocation endpoint appears in discovery.
func Test_Revocation_AdvertisedInDiscovery(t *testing.T) {
	if testClient.Discovery.RevocationEndpoint == "" {
		t.Fatal("expected revocation_endpoint in discovery document, got empty")
	}
}

// Test_Revocation_RefreshToken obtains a refresh token then revokes it;
// a subsequent refresh token exchange must fail with invalid_grant.
func Test_Revocation_RefreshToken(t *testing.T) {
	testClient.Reset()
	refreshToken := getRefreshTokenViaPassword(t)

	// Revoke the refresh token.
	revokeReq := testClient.NewRequest("POST", testClient.Discovery.RevocationEndpoint)
	revokeReq.SetBasicAuth("myclient", "secret")
	revokeReq.AddForm("token", refreshToken)
	revokeReq.AddForm("token_type_hint", "refresh_token")

	revokeResp, err := revokeReq.Send()
	if err != nil {
		t.Fatalf("revoke request error: %v", err)
	}
	defer revokeResp.Close()

	if revokeResp.StatusCode() != http.StatusNoContent {
		t.Fatalf("expected 204 from revocation, got %d", revokeResp.StatusCode())
	}

	// Try to use the revoked refresh token — must fail.
	testClient.Reset()
	retryReq := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	retryReq.SetBasicAuth("myclient", "secret")
	retryReq.AddForm("grant_type", "refresh_token")
	retryReq.AddForm("refresh_token", refreshToken)

	retryResp, err := retryReq.Send()
	if err != nil {
		t.Fatalf("retry refresh error: %v", err)
	}
	defer retryResp.Close()

	if retryResp.StatusCode() != http.StatusUnauthorized {
		t.Fatalf("expected 401 after revoked refresh token use, got %d", retryResp.StatusCode())
	}

	errBody := &ErrorResponse{}
	if err := retryResp.BodyAsJSON(errBody); err != nil {
		t.Fatalf("cannot parse error response: %v", err)
	}
	if errBody.Error != "invalid_grant" {
		t.Fatalf("expected error=invalid_grant, got %q", errBody.Error)
	}
}

// Test_Revocation_AccessToken revokes an access token (best-effort / advisory for JWTs).
func Test_Revocation_AccessToken(t *testing.T) {
	testClient.Reset()
	// Get an access token via the password grant.
	tokenReq := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	tokenReq.SetBasicAuth("myclient", "secret")
	tokenReq.AddForm("grant_type", "password")
	tokenReq.AddForm("username", "user")
	tokenReq.AddForm("password", "password")
	tokenReq.AddForm("scope", "openid email")

	tokenResp, err := tokenReq.Send()
	if err != nil {
		t.Fatalf("password grant error: %v", err)
	}
	defer tokenResp.Close()

	if tokenResp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200, got %d", tokenResp.StatusCode())
	}

	tokens := &TokenResponse{}
	if err := tokenResp.BodyAsJSON(tokens); err != nil {
		t.Fatalf("cannot parse token response: %v", err)
	}

	// Revoke the access token.
	revokeReq := testClient.NewRequest("POST", testClient.Discovery.RevocationEndpoint)
	revokeReq.SetBasicAuth("myclient", "secret")
	revokeReq.AddForm("token", tokens.AccessToken)
	revokeReq.AddForm("token_type_hint", "access_token")

	revokeResp, err := revokeReq.Send()
	if err != nil {
		t.Fatalf("revoke request error: %v", err)
	}
	defer revokeResp.Close()

	if revokeResp.StatusCode() != http.StatusNoContent {
		t.Fatalf("expected 204 from access token revocation, got %d", revokeResp.StatusCode())
	}
}

// Test_Revocation_InvalidClient verifies that revocation with a wrong secret returns 401.
func Test_Revocation_InvalidClient(t *testing.T) {
	testClient.Reset()

	revokeReq := testClient.NewRequest("POST", testClient.Discovery.RevocationEndpoint)
	revokeReq.SetBasicAuth("myclient", "wrongsecret")
	revokeReq.AddForm("token", "sometoken")

	revokeResp, err := revokeReq.Send()
	if err != nil {
		t.Fatalf("revoke request error: %v", err)
	}
	defer revokeResp.Close()

	if revokeResp.StatusCode() != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid client, got %d", revokeResp.StatusCode())
	}
}

// Test_Revocation_MissingToken verifies that a missing token parameter returns 400.
func Test_Revocation_MissingToken(t *testing.T) {
	testClient.Reset()

	revokeReq := testClient.NewRequest("POST", testClient.Discovery.RevocationEndpoint)
	revokeReq.SetBasicAuth("myclient", "secret")
	// Intentionally omit "token" param.

	revokeResp, err := revokeReq.Send()
	if err != nil {
		t.Fatalf("revoke request error: %v", err)
	}
	defer revokeResp.Close()

	if revokeResp.StatusCode() != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing token, got %d", revokeResp.StatusCode())
	}
}

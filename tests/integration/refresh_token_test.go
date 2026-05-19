package integration

import (
	"net/http"
	"testing"
)

// getRefreshTokenViaPassword is a helper that obtains a refresh token by performing
// a password grant with the offline_access scope.
func getRefreshTokenViaPassword(t *testing.T) string {
	t.Helper()
	req := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	req.SetBasicAuth("myclient", "secret")
	req.AddForm("grant_type", "password")
	req.AddForm("username", "user")
	req.AddForm("password", "password")
	req.AddForm("scope", "openid offline_access")

	resp, err := req.Send()
	if err != nil {
		t.Fatalf("password grant error: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200 from password grant, got %d", resp.StatusCode())
	}

	tokens := &TokenResponse{}
	if err := resp.BodyAsJSON(tokens); err != nil {
		t.Fatalf("cannot parse password grant response: %v", err)
	}
	if tokens.RefreshToken == nil || *tokens.RefreshToken == "" {
		t.Fatal("expected a refresh_token in the password grant response")
	}
	return *tokens.RefreshToken
}

func Test_RefreshToken(t *testing.T) {
	t.Run("valid_refresh_token_issues_new_access_token", func(t *testing.T) {
		refreshToken := getRefreshTokenViaPassword(t)

		req := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
		req.SetBasicAuth("myclient", "secret")
		req.AddForm("grant_type", "refresh_token")
		req.AddForm("refresh_token", refreshToken)

		resp, err := req.Send()
		if err != nil {
			t.Fatalf("refresh token request error: %v", err)
		}
		defer resp.Close()

		if resp.StatusCode() != http.StatusOK {
			t.Fatalf("expected 200 for valid refresh token, got %d", resp.StatusCode())
		}

		tokens := &TokenResponse{}
		if err := resp.BodyAsJSON(tokens); err != nil {
			t.Fatalf("cannot parse refresh token response: %v", err)
		}
		if tokens.AccessToken == "" {
			t.Fatal("expected access_token in refresh response")
		}
		if tokens.TokenType != "bearer" {
			t.Fatalf("expected token_type=bearer, got %q", tokens.TokenType)
		}
		if tokens.ExpiresIn == 0 {
			t.Fatal("expected expires_in > 0 in refresh response")
		}
	})

	t.Run("invalid_refresh_token_returns_error", func(t *testing.T) {
		req := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
		req.SetBasicAuth("myclient", "secret")
		req.AddForm("grant_type", "refresh_token")
		req.AddForm("refresh_token", "this_is_not_a_valid_refresh_token")

		resp, err := req.Send()
		if err != nil {
			t.Fatalf("refresh token request error: %v", err)
		}
		defer resp.Close()

		if resp.StatusCode() != http.StatusUnauthorized && resp.StatusCode() != http.StatusBadRequest {
			t.Fatalf("expected 401 or 400 for invalid refresh token, got %d", resp.StatusCode())
		}
	})

	t.Run("missing_refresh_token_returns_error", func(t *testing.T) {
		req := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
		req.SetBasicAuth("myclient", "secret")
		req.AddForm("grant_type", "refresh_token")
		// intentionally omit refresh_token

		resp, err := req.Send()
		if err != nil {
			t.Fatalf("refresh token request error: %v", err)
		}
		defer resp.Close()

		if resp.StatusCode() != http.StatusBadRequest {
			t.Fatalf("expected 400 for missing refresh_token, got %d", resp.StatusCode())
		}
	})
}

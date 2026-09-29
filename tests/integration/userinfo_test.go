package integration

import (
	"encoding/json"
	"net/http"
	"testing"
)

type userinfoResponse struct {
	Sub               string `json:"sub,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Email             string `json:"email,omitempty"`
}

// getAccessToken is a helper that returns an access token obtained via the
// password grant for the given scope.
func getAccessToken(t *testing.T, scope string) string {
	t.Helper()
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
		t.Fatalf("expected 200 from password grant, got %d", resp.StatusCode())
	}

	tokens := &TokenResponse{}
	if err := resp.BodyAsJSON(tokens); err != nil {
		t.Fatalf("cannot parse password grant response: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Fatal("expected access_token in response")
	}
	return tokens.AccessToken
}

func Test_UserInfo(t *testing.T) {
	t.Run("valid_token_with_profile_scope_returns_preferred_username", func(t *testing.T) {
		accessToken := getAccessToken(t, "profile")

		req := testClient.NewRequest("GET", testClient.Discovery.UserinfoEndpoint)
		req.SetHeader("Authorization", "Bearer "+accessToken)

		resp, err := req.Send()
		if err != nil {
			t.Fatalf("userinfo GET error: %v", err)
		}
		defer resp.Close()

		if resp.StatusCode() != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode())
		}

		body := resp.BodyAsString()
		var claims userinfoResponse
		if err := json.Unmarshal([]byte(body), &claims); err != nil {
			t.Fatalf("cannot parse userinfo response: %v", err)
		}
		if claims.PreferredUsername != "user" {
			t.Fatalf("expected preferred_username=%q, got %q", "user", claims.PreferredUsername)
		}
	})

	t.Run("missing_authorization_header_returns_401", func(t *testing.T) {
		req := testClient.NewRequest("GET", testClient.Discovery.UserinfoEndpoint)
		// no Authorization header

		resp, err := req.Send()
		if err != nil {
			t.Fatalf("userinfo GET error: %v", err)
		}
		defer resp.Close()

		if resp.StatusCode() != http.StatusUnauthorized {
			t.Fatalf("expected 401 for missing token, got %d", resp.StatusCode())
		}
	})

	t.Run("invalid_token_returns_401", func(t *testing.T) {
		req := testClient.NewRequest("GET", testClient.Discovery.UserinfoEndpoint)
		req.SetHeader("Authorization", "Bearer this_is_not_a_valid_jwt_token")

		resp, err := req.Send()
		if err != nil {
			t.Fatalf("userinfo GET error: %v", err)
		}
		defer resp.Close()

		if resp.StatusCode() != http.StatusUnauthorized {
			t.Fatalf("expected 401 for invalid token, got %d", resp.StatusCode())
		}
	})

	t.Run("malformed_authorization_header_returns_401", func(t *testing.T) {
		req := testClient.NewRequest("GET", testClient.Discovery.UserinfoEndpoint)
		req.SetHeader("Authorization", "NotBearer sometoken")

		resp, err := req.Send()
		if err != nil {
			t.Fatalf("userinfo GET error: %v", err)
		}
		defer resp.Close()

		if resp.StatusCode() != http.StatusUnauthorized {
			t.Fatalf("expected 401 for malformed authorization header, got %d", resp.StatusCode())
		}
	})
}

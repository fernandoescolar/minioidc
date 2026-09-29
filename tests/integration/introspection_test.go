package integration

import (
	"encoding/json"
	"net/http"
	"testing"
)

type introspectionResult struct {
	// Active is a bool when the token is valid, and a string "false" when inactive.
	// We use interface{} and check the actual value to handle both.
	rawActive interface{}
	Sub       string `json:"sub,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
}

func parseIntrospectionBody(t *testing.T, body string) map[string]interface{} {
	t.Helper()
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("cannot parse introspection response: %v\nbody: %s", err, body)
	}
	return result
}

func isActiveToken(result map[string]interface{}) bool {
	v, ok := result["active"]
	if !ok {
		return false
	}
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return val == "true"
	}
	return false
}

func Test_Introspection(t *testing.T) {
	t.Run("valid_access_token_returns_active_true", func(t *testing.T) {
		accessToken := getAccessToken(t, "email")

		req := testClient.NewRequest("POST", testClient.Discovery.IntrospectionEndpoint)
		req.SetBasicAuth("myclient", "secret")
		req.AddForm("token", accessToken)

		resp, err := req.Send()
		if err != nil {
			t.Fatalf("introspection POST error: %v", err)
		}
		defer resp.Close()

		if resp.StatusCode() != http.StatusOK {
			t.Fatalf("expected 200 for valid token introspection, got %d", resp.StatusCode())
		}

		result := parseIntrospectionBody(t, resp.BodyAsString())
		if !isActiveToken(result) {
			t.Fatalf("expected active=true for valid token, got: %v", result["active"])
		}
		if result["sub"] == "" || result["sub"] == nil {
			t.Error("expected non-empty sub claim in introspection response")
		}
		if result["exp"] == nil {
			t.Error("expected exp claim in introspection response")
		}
		if result["iat"] == nil {
			t.Error("expected iat claim in introspection response")
		}
	})

	t.Run("invalid_token_returns_inactive", func(t *testing.T) {
		req := testClient.NewRequest("POST", testClient.Discovery.IntrospectionEndpoint)
		req.SetBasicAuth("myclient", "secret")
		req.AddForm("token", "this.is.not.a.valid.jwt.token")

		resp, err := req.Send()
		if err != nil {
			t.Fatalf("introspection POST error: %v", err)
		}
		defer resp.Close()

		// RFC 7662: inactive tokens MUST return active=false with 200, not an error.
		if resp.StatusCode() != http.StatusOK {
			t.Fatalf("expected 200 for inactive token introspection, got %d", resp.StatusCode())
		}

		result := parseIntrospectionBody(t, resp.BodyAsString())
		if isActiveToken(result) {
			t.Fatal("expected active=false for invalid token")
		}
	})

	t.Run("missing_token_returns_400", func(t *testing.T) {
		req := testClient.NewRequest("POST", testClient.Discovery.IntrospectionEndpoint)
		req.SetBasicAuth("myclient", "secret")
		// omit token parameter

		resp, err := req.Send()
		if err != nil {
			t.Fatalf("introspection POST error: %v", err)
		}
		defer resp.Close()

		if resp.StatusCode() != http.StatusBadRequest {
			t.Fatalf("expected 400 for missing token, got %d", resp.StatusCode())
		}
	})

	t.Run("missing_client_auth_returns_400", func(t *testing.T) {
		accessToken := getAccessToken(t, "email")

		req := testClient.NewRequest("POST", testClient.Discovery.IntrospectionEndpoint)
		// no Basic Auth
		req.AddForm("token", accessToken)

		resp, err := req.Send()
		if err != nil {
			t.Fatalf("introspection POST error: %v", err)
		}
		defer resp.Close()

		if resp.StatusCode() != http.StatusBadRequest && resp.StatusCode() != http.StatusUnauthorized {
			t.Fatalf("expected 400 or 401 for missing client auth, got %d", resp.StatusCode())
		}
	})

	t.Run("invalid_client_secret_returns_401", func(t *testing.T) {
		accessToken := getAccessToken(t, "email")

		req := testClient.NewRequest("POST", testClient.Discovery.IntrospectionEndpoint)
		req.SetBasicAuth("myclient", "wrong_secret")
		req.AddForm("token", accessToken)

		resp, err := req.Send()
		if err != nil {
			t.Fatalf("introspection POST error: %v", err)
		}
		defer resp.Close()

		if resp.StatusCode() != http.StatusUnauthorized {
			t.Fatalf("expected 401 for invalid client secret, got %d", resp.StatusCode())
		}
	})
}

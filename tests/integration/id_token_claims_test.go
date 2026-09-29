package integration

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// decodeJWTPayload decodes the payload (middle) segment of a JWT without
// verifying the signature.  The returned map contains all standard claims.
func decodeJWTPayload(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("cannot decode JWT payload: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("cannot unmarshal JWT payload: %v", err)
	}
	return claims
}

// getIDToken returns an ID token by performing a password grant with openid scope.
func getIDToken(t *testing.T, extraScope string) string {
	t.Helper()
	scope := "openid"
	if extraScope != "" {
		scope += " " + extraScope
	}

	req := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	req.SetBasicAuth("myclient", "secret")
	req.AddForm("grant_type", "password")
	req.AddForm("username", "user")
	req.AddForm("password", "password")
	req.AddForm("scope", scope)

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
		t.Fatalf("cannot parse token response: %v", err)
	}
	if tokens.IDToken == nil || *tokens.IDToken == "" {
		t.Fatal("expected id_token in response")
	}
	return *tokens.IDToken
}

func Test_IDTokenClaims(t *testing.T) {
	t.Run("issuer_claim_matches_server_issuer", func(t *testing.T) {
		idToken := getIDToken(t, "")
		claims := decodeJWTPayload(t, idToken)

		iss, ok := claims["iss"].(string)
		if !ok || iss == "" {
			t.Fatal("expected non-empty iss claim")
		}
		if iss != fakeIssuer {
			t.Fatalf("expected iss=%q, got %q", fakeIssuer, iss)
		}
	})

	t.Run("subject_claim_is_non_empty", func(t *testing.T) {
		idToken := getIDToken(t, "")
		claims := decodeJWTPayload(t, idToken)

		sub, ok := claims["sub"].(string)
		if !ok || sub == "" {
			t.Fatal("expected non-empty sub claim")
		}
	})

	t.Run("audience_claim_contains_client_id", func(t *testing.T) {
		idToken := getIDToken(t, "")
		claims := decodeJWTPayload(t, idToken)

		aud := claims["aud"]
		if aud == nil {
			t.Fatal("expected aud claim")
		}
		// aud can be a string or []interface{}
		found := false
		switch v := aud.(type) {
		case string:
			found = v == "myclient"
		case []interface{}:
			for _, a := range v {
				if a.(string) == "myclient" {
					found = true
					break
				}
			}
		}
		if !found {
			t.Fatalf("expected aud to contain 'myclient', got: %v", aud)
		}
	})

	t.Run("expiry_is_in_the_future", func(t *testing.T) {
		idToken := getIDToken(t, "")
		claims := decodeJWTPayload(t, idToken)

		exp, ok := claims["exp"].(float64)
		if !ok {
			t.Fatal("expected numeric exp claim")
		}
		if time.Unix(int64(exp), 0).Before(time.Now()) {
			t.Fatalf("id_token is already expired: exp=%v", time.Unix(int64(exp), 0))
		}
	})

	t.Run("issued_at_is_before_expiry", func(t *testing.T) {
		idToken := getIDToken(t, "")
		claims := decodeJWTPayload(t, idToken)

		iat, ok := claims["iat"].(float64)
		if !ok {
			t.Fatal("expected numeric iat claim")
		}
		exp, ok := claims["exp"].(float64)
		if !ok {
			t.Fatal("expected numeric exp claim")
		}
		if iat >= exp {
			t.Fatalf("iat (%v) must be before exp (%v)", iat, exp)
		}
	})

	t.Run("nonce_included_in_authorization_code_flow", func(t *testing.T) {
		// Perform the full authorization code flow with a nonce so we can verify
		// the nonce lands in the id_token.
		testClient.Reset()
		tc := authorizationTestCase{
			clientID:           "myclient",
			secret:             "secret",
			username:           "user",
			password:           "password",
			scope:              "openid email",
			responseType:       "code",
			redirectURI:        "http://localhost/callback",
			expectedStatus:     http.StatusOK,
			expectAccessToken:  true,
			expectdIDToken:     true,
			expectRefreshToken: false,
		}
		nonce := "test_nonce_value_123"
		tc.nonce = &nonce

		_, callbackURL := runAuthorizationFlowAndLogin(t, tc)
		if callbackURL == nil {
			t.Fatal("expected a callback URL from the authorization flow")
		}
		code := callbackURL.Query().Get("code")
		if code == "" {
			t.Fatal("expected code in callback URL")
		}

		tokenReq := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
		tokenReq.SetBasicAuth("myclient", "secret")
		tokenReq.AddForm("grant_type", "authorization_code")
		tokenReq.AddForm("code", code)
		tokenReq.AddForm("redirect_uri", "http://localhost/callback")
		tokenReq.AddForm("nonce", nonce)

		tokenResp, err := tokenReq.Send()
		if err != nil {
			t.Fatalf("token exchange error: %v", err)
		}
		defer tokenResp.Close()

		tokens := &TokenResponse{}
		if err := tokenResp.BodyAsJSON(tokens); err != nil {
			t.Fatalf("cannot parse token response: %v", err)
		}
		if tokens.IDToken == nil {
			t.Fatal("expected id_token")
		}

		idClaims := decodeJWTPayload(t, *tokens.IDToken)
		n, ok := idClaims["nonce"].(string)
		if !ok || n != nonce {
			t.Fatalf("expected nonce=%q in id_token, got %v", nonce, idClaims["nonce"])
		}
	})

	t.Run("email_scope_adds_email_claims", func(t *testing.T) {
		idToken := getIDToken(t, "email")
		claims := decodeJWTPayload(t, idToken)

		// email_verified should be present when email scope is requested
		if _, ok := claims["email_verified"]; !ok {
			t.Error("expected email_verified claim with email scope")
		}
	})

	t.Run("profile_scope_adds_preferred_username", func(t *testing.T) {
		idToken := getIDToken(t, "profile")
		claims := decodeJWTPayload(t, idToken)

		username, ok := claims["preferred_username"].(string)
		if !ok || username == "" {
			t.Error("expected non-empty preferred_username claim with profile scope")
		}
		if username != "user" {
			t.Errorf("expected preferred_username=%q, got %q", "user", username)
		}
	})
}

package integration

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"
)

type pkceTestCase struct {
	name              string
	challengeMethod   string
	verifier          string // verifier to send at token exchange (may differ from the one used to generate challenge)
	expectTokenStatus int
}

func Test_Authorization_PKCE(t *testing.T) {
	validVerifier := generateCodeVerifier(t)
	wrongVerifier := generateCodeVerifier(t)

	testCases := []pkceTestCase{
		{
			name:              "S256 with correct verifier",
			challengeMethod:   "S256",
			verifier:          validVerifier,
			expectTokenStatus: http.StatusOK,
		},
		{
			name:              "plain with correct verifier",
			challengeMethod:   "plain",
			verifier:          validVerifier,
			expectTokenStatus: http.StatusOK,
		},
		{
			name:              "S256 with wrong verifier",
			challengeMethod:   "S256",
			verifier:          wrongVerifier,
			expectTokenStatus: http.StatusUnauthorized,
		},
		{
			name:              "S256 with missing verifier",
			challengeMethod:   "S256",
			verifier:          "", // omit code_verifier at token exchange
			expectTokenStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			testClient.Reset()

			// Compute the code_challenge from validVerifier (the one used during authorize)
			challenge := generateCodeChallenge(t, tc.challengeMethod, validVerifier)

			// --- Step 1: GET /connect/authorize with code_challenge ---
			authReq := testClient.NewRequest("GET", testClient.Discovery.AuthorizationEndpoint)
			authReq.AddQuery("client_id", "myclient")
			authReq.AddQuery("response_type", "code")
			authReq.AddQuery("redirect_uri", "http://localhost/callback")
			authReq.AddQuery("scope", "email")
			authReq.AddQuery("state", ValidState)
			authReq.AddQuery("nonce", ValidNonce)
			authReq.AddQuery("code_challenge", challenge)
			authReq.AddQuery("code_challenge_method", tc.challengeMethod)

			authResp, err := authReq.Send()
			if err != nil {
				t.Fatalf("authorize GET error: %v", err)
			}
			if authResp.StatusCode() != http.StatusOK {
				t.Fatalf("expected login page (200), got %d", authResp.StatusCode())
			}

			// --- Step 2: POST /login ---
			loginReq := createLoginRequest(authResp, "user", "password")
			authResp.Close()

			_, loginErr := loginReq.Send()
			urlError, ok := loginErr.(*url.Error)
			if !ok {
				t.Fatal("expected url.Error (redirect to callback) after login")
			}
			callbackURL, parseErr := url.ParseRequestURI(urlError.URL)
			if parseErr != nil {
				t.Fatalf("cannot parse callback URL: %v", parseErr)
			}
			code := callbackURL.Query().Get("code")
			if code == "" {
				t.Fatal("expected code in callback URL")
			}

			// --- Step 3: POST /connect/token ---
			tokenReq := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
			tokenReq.SetBasicAuth("myclient", "secret")
			tokenReq.AddForm("grant_type", "authorization_code")
			tokenReq.AddForm("code", code)
			tokenReq.AddForm("redirect_uri", "http://localhost/callback")
			if tc.verifier != "" {
				tokenReq.AddForm("code_verifier", tc.verifier)
			}

			tokenResp, err := tokenReq.Send()
			if err != nil {
				t.Fatalf("token POST error: %v", err)
			}
			defer tokenResp.Close()

			if tokenResp.StatusCode() != tc.expectTokenStatus {
				t.Fatalf("expected token status %d, got %d", tc.expectTokenStatus, tokenResp.StatusCode())
			}

			if tc.expectTokenStatus == http.StatusOK {
				tokens := &TokenResponse{}
				if err := tokenResp.BodyAsJSON(tokens); err != nil {
					t.Fatalf("cannot parse token response: %v", err)
				}
				if tokens.AccessToken == "" {
					t.Fatal("expected access_token in response")
				}
			}
		})
	}
}

// generateCodeVerifier returns a cryptographically random PKCE code verifier
// (43 random bytes, base64url-encoded without padding = 58 chars).
func generateCodeVerifier(t *testing.T) string {
	t.Helper()
	b := make([]byte, 43)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generateCodeVerifier: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// generateCodeChallenge produces the PKCE code_challenge for a given method
// and verifier, mirroring the server-side cryptography.GenerateCodeChallenge.
func generateCodeChallenge(t *testing.T, method, verifier string) string {
	t.Helper()
	switch method {
	case "S256":
		sum := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(sum[:])
	case "plain":
		return verifier
	default:
		t.Fatalf("unknown PKCE method: %s", method)
		return ""
	}
}

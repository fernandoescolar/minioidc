package integration

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"testing"
)

const (
	ValidNonce = "nonce123"
	ValidState = "state123"
)

type authorizationTestCase struct {
	name               string
	clientID           string
	secret             string
	username           string
	password           string
	responseType       string
	scope              string
	redirectURI        string
	nonce              *string // by default use ValidNonce
	state              *string // by default use ValidState
	prompt             *string
	maxAge             *int
	expectedStatus     int
	expectAccessToken  bool
	expectdIDToken     bool
	expectRefreshToken bool
}

func Test_Authorization_Basic(t *testing.T) {
	testCases := []authorizationTestCase{
		{
			name:               "valid client and user",
			clientID:           "myclient",
			secret:             "secret",
			username:           "user",
			password:           "password",
			scope:              "email",
			responseType:       "code",
			redirectURI:        "http://localhost/callback",
			expectedStatus:     http.StatusOK,
			expectAccessToken:  true,
			expectdIDToken:     false,
			expectRefreshToken: false,
		},
		{
			name:               "valid client and user with id_token",
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
		},
		{
			name:               "valid client and user with refresh token",
			clientID:           "myclient",
			secret:             "secret",
			username:           "user",
			password:           "password",
			scope:              "openid email offline_access",
			responseType:       "code",
			redirectURI:        "http://localhost/callback",
			expectedStatus:     http.StatusOK,
			expectAccessToken:  true,
			expectdIDToken:     true,
			expectRefreshToken: true,
		},
	}

	for _, tc := range testCases {
		name := fmt.Sprintf("Authorization_%s", tc.name)
		t.Run(name, func(t *testing.T) {
			testClient.Reset()
			req := createAuthorizationRequest(tc, false)
			runAndValidateAuthorizationTest(t, req, tc)
		})
	}
}

// Test_Authorization_Errors covers all authorization-code-flow error scenarios.
// These require a different test structure because errors can occur at different
// points in the redirect chain (before login, during login, after login at the
// authorize endpoint).
func Test_Authorization_Errors(t *testing.T) {
	t.Run("invalid_client", func(t *testing.T) {
		testClient.Reset()
		tc := authorizationTestCase{
			clientID:     "invalid_client_id",
			secret:       "secret",
			username:     "user",
			password:     "password",
			scope:        "email",
			responseType: "code",
			redirectURI:  "http://localhost/callback",
		}
		// After valid login, the authorize endpoint should reject the unknown client.
		loginResp, callbackURL := runAuthorizationFlowAndLogin(t, tc)
		if callbackURL != nil {
			t.Fatal("expected error response but got a redirect to the callback")
		}
		defer loginResp.Close()
		if loginResp.StatusCode() != http.StatusUnauthorized {
			t.Fatalf("expected status %d for invalid client, got %d", http.StatusUnauthorized, loginResp.StatusCode())
		}
	})

	t.Run("invalid_user", func(t *testing.T) {
		testClient.Reset()
		tc := authorizationTestCase{
			clientID:     "myclient",
			secret:       "secret",
			username:     "invalid_user",
			password:     "password",
			scope:        "email",
			responseType: "code",
			redirectURI:  "http://localhost/callback",
		}
		// Invalid username → login form is re-rendered (status 200), no callback redirect.
		loginResp, callbackURL := runAuthorizationFlowAndLogin(t, tc)
		if callbackURL != nil {
			t.Fatal("expected login failure but got a redirect to the callback")
		}
		defer loginResp.Close()
		if loginResp.StatusCode() != http.StatusOK {
			t.Fatalf("expected login page re-render (200) for invalid user, got %d", loginResp.StatusCode())
		}
	})

	t.Run("invalid_password", func(t *testing.T) {
		testClient.Reset()
		tc := authorizationTestCase{
			clientID:     "myclient",
			secret:       "secret",
			username:     "user",
			password:     "wrong_password",
			scope:        "email",
			responseType: "code",
			redirectURI:  "http://localhost/callback",
		}
		// Invalid password → login form is re-rendered (status 200), no callback redirect.
		loginResp, callbackURL := runAuthorizationFlowAndLogin(t, tc)
		if callbackURL != nil {
			t.Fatal("expected login failure but got a redirect to the callback")
		}
		defer loginResp.Close()
		if loginResp.StatusCode() != http.StatusOK {
			t.Fatalf("expected login page re-render (200) for invalid password, got %d", loginResp.StatusCode())
		}
	})

	t.Run("invalid_scope", func(t *testing.T) {
		testClient.Reset()
		tc := authorizationTestCase{
			clientID:     "myclient",
			secret:       "secret",
			username:     "user",
			password:     "password",
			scope:        "not_a_real_scope",
			responseType: "code",
			redirectURI:  "http://localhost/callback",
		}
		// After valid login, the authorize endpoint should reject the unknown scope.
		loginResp, callbackURL := runAuthorizationFlowAndLogin(t, tc)
		if callbackURL != nil {
			t.Fatal("expected error response but got a redirect to the callback")
		}
		defer loginResp.Close()
		if loginResp.StatusCode() != http.StatusBadRequest {
			t.Fatalf("expected status %d for invalid scope, got %d", http.StatusBadRequest, loginResp.StatusCode())
		}
	})

	t.Run("invalid_redirect_uri", func(t *testing.T) {
		testClient.Reset()
		tc := authorizationTestCase{
			clientID:     "myclient",
			secret:       "secret",
			username:     "user",
			password:     "password",
			scope:        "email",
			responseType: "code",
			redirectURI:  "http://evil.example.com/callback",
		}
		// After valid login, the authorize endpoint should reject the unregistered redirect_uri.
		loginResp, callbackURL := runAuthorizationFlowAndLogin(t, tc)
		if callbackURL != nil {
			t.Fatal("expected error response but got a redirect to the callback")
		}
		defer loginResp.Close()
		if loginResp.StatusCode() != http.StatusBadRequest {
			t.Fatalf("expected status %d for invalid redirect_uri, got %d", http.StatusBadRequest, loginResp.StatusCode())
		}
	})
}

// runAuthorizationFlowAndLogin drives the full authorize→login→authorize redirect chain.
// On success (valid client + scope + credentials), the HTTP client eventually tries to
// reach the callback URI, which fails with a *url.Error; callbackURL is populated and
// loginResp is nil.
// On error (bad credentials, invalid client, invalid scope, …) the chain ends with a
// non-redirect response; loginResp is populated and callbackURL is nil.
func runAuthorizationFlowAndLogin(t *testing.T, tc authorizationTestCase) (loginResp *ClientResponse, callbackURL *url.URL) {
	t.Helper()

	req := createAuthorizationRequest(tc, false)

	// Step 1: GET /connect/authorize → session middleware redirects to login
	resp, err := req.Send()
	if err != nil {
		t.Fatalf("authorize GET unexpected error: %v", err)
	}
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected login page (200) after authorize redirect, got %d", resp.StatusCode())
	}

	// Step 2: POST /login
	loginReq := createLoginRequest(resp, tc.username, tc.password)
	resp.Close()

	postResp, postErr := loginReq.Send()
	if postErr != nil {
		// The HTTP client followed redirects and ended up at a URL it couldn't connect to.
		// That means the flow succeeded: the authorize endpoint redirected to the callback.
		urlErr, ok := postErr.(*url.Error)
		if !ok {
			t.Fatalf("unexpected non-URL error after login POST: %v", postErr)
		}
		u, parseErr := url.ParseRequestURI(urlErr.URL)
		if parseErr != nil {
			t.Fatalf("cannot parse callback URL %q: %v", urlErr.URL, parseErr)
		}
		return nil, u
	}

	// Login returned a normal response (error case: bad credentials, invalid client, etc.)
	return postResp, nil
}

func createAuthorizationRequest(testCase authorizationTestCase, clientBasic bool) *ClientRequest {
	req := testClient.NewRequest("GET", testClient.Discovery.AuthorizationEndpoint)
	if clientBasic {
		req.SetBasicAuth(testCase.clientID, testCase.secret)
	} else {
		req.AddQuery("client_id", testCase.clientID)
		req.AddQuery("client_secret", testCase.secret)
	}

	req.AddQuery("grant_type", "authorization")
	req.AddQuery("response_type", testCase.responseType)
	req.AddQuery("redirect_uri", testCase.redirectURI)

	if testCase.nonce != nil {
		req.AddQuery("nonce", *testCase.nonce)
	} else {
		req.AddQuery("nonce", ValidNonce)
	}

	if testCase.state != nil {
		req.AddQuery("state", *testCase.state)
	} else {
		req.AddQuery("state", ValidState)
	}

	if testCase.scope != "" {
		req.AddQuery("scope", testCase.scope)
	}
	if testCase.prompt != nil {
		req.AddQuery("prompt", *testCase.prompt)
	}
	if testCase.maxAge != nil {
		req.AddQuery("max_age", fmt.Sprintf("%d", *testCase.maxAge))
	}

	return req
}

func runAndValidateAuthorizationTest(t *testing.T, request *ClientRequest, testCase authorizationTestCase) {
	t.Helper()

	resp, err := request.Send()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected login page status %d, got %d", http.StatusOK, resp.StatusCode())
	}

	request = createLoginRequest(resp, testCase.username, testCase.password)
	resp.Close()

	_, err = request.Send()
	urlError, ok := err.(*url.Error)
	if !ok {
		t.Fatal("expected url.Error (redirect to callback) after login, got nil")
	}
	urlResponse, err := url.ParseRequestURI(urlError.URL)
	if err != nil {
		t.Fatalf("cannot parse callback URL: %v", err)
	}

	q := urlResponse.Query()
	if q.Get("state") != ValidState {
		t.Fatalf("expected state %q, got %q", ValidState, q.Get("state"))
	}

	code := q.Get("code")
	if code == "" {
		t.Fatal("expected code in callback URL, got empty")
	}

	request = testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	request.SetBasicAuth(testCase.clientID, testCase.secret)
	request.AddForm("grant_type", "authorization_code")
	request.AddForm("code", code)
	request.AddForm("redirect_uri", testCase.redirectURI)
	if testCase.nonce != nil {
		request.AddForm("nonce", *testCase.nonce)
	} else {
		request.AddForm("nonce", ValidNonce)
	}
	resp, err = request.Send()
	if err != nil {
		t.Fatal(err)
	}

	defer resp.Close()
	if resp.StatusCode() != testCase.expectedStatus {
		t.Fatalf("expected token response status %d, got %d", testCase.expectedStatus, resp.StatusCode())
	}

	if testCase.expectedStatus >= http.StatusBadRequest {
		return
	}

	tokens := &TokenResponse{}
	if err = resp.BodyAsJSON(tokens); err != nil {
		t.Fatal(err)
	}

	if tokens.AccessToken == "" && testCase.expectAccessToken {
		t.Fatal("expected access token, got empty")
	}
	if tokens.AccessToken != "" && !testCase.expectAccessToken {
		t.Fatal("did not expect access token, but got one")
	}

	if tokens.IDToken == nil && testCase.expectdIDToken {
		t.Fatal("expected id_token, got nil")
	}
	if tokens.IDToken != nil && !testCase.expectdIDToken {
		t.Fatal("did not expect id_token, but got one")
	}

	if tokens.RefreshToken == nil && testCase.expectRefreshToken {
		t.Fatal("expected refresh_token, got nil")
	}
	if tokens.RefreshToken != nil && !testCase.expectRefreshToken {
		t.Fatal("did not expect refresh_token, but got one")
	}

	if tokens.TokenType != "bearer" {
		t.Fatalf("expected token type %q, got %q", "bearer", tokens.TokenType)
	}

	if tokens.ExpiresIn == 0 {
		t.Fatalf("expected expires_in > 0, got %d", tokens.ExpiresIn)
	}
}

func createLoginRequest(r *ClientResponse, username, password string) *ClientRequest {
	req := testClient.NewRequest("POST", r.FullURLPath())
	req.AddForm("username", username)
	req.AddForm("password", password)
	req.AddForm("__csrf", getCSRFValue(r))

	return req
}

func getCSRFValue(r *ClientResponse) string {
	rexp := regexp.MustCompile(`<input[^>]+\bname="__csrf"[^>]*>`)
	matches := rexp.FindStringSubmatch(r.BodyAsString())
	if len(matches) != 1 {
		return ""
	}

	rexp = regexp.MustCompile(`value="([^"]*)"`)
	matches = rexp.FindStringSubmatch(matches[0])
	if len(matches) != 2 {
		return ""
	}

	return html.UnescapeString(matches[1])
}

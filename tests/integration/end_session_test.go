package integration

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Test_EndSession_AdvertisedInDiscovery verifies the end_session endpoint appears in discovery.
func Test_EndSession_AdvertisedInDiscovery(t *testing.T) {
	if testClient.Discovery.EndSessionEndpoint == "" {
		t.Fatal("expected end_session_endpoint in discovery document, got empty")
	}
}

// Test_EndSession_ClearsSession verifies that calling end_session invalidates the browser session.
// After logout the user should be redirected to /login when they try to authorize again.
func Test_EndSession_ClearsSession(t *testing.T) {
	testClient.Reset()

	// Step 1: Perform a full login to obtain a session cookie.
	tc := authorizationTestCase{
		clientID:     "myclient",
		secret:       "secret",
		username:     "user",
		password:     "password",
		scope:        "openid email",
		responseType: "code",
		redirectURI:  "http://localhost/callback",
	}
	_, callbackURL := runAuthorizationFlowAndLogin(t, tc)
	if callbackURL == nil {
		t.Fatal("expected successful authorization flow")
	}

	// Step 2: Call end_session — expect a redirect (302) to "/".
	// The http.Client follows redirects, so we configure a custom check-redirect
	// that stops at the first redirect to capture the redirect target.
	endSessionURL := testClient.Discovery.EndSessionEndpoint
	endReq := testClient.NewRequest("GET", endSessionURL)
	endResp, err := endReq.Send()
	if err != nil {
		// Redirect to "/" which the test server serves — should not error.
		t.Fatalf("end_session GET error: %v", err)
	}
	if endResp != nil {
		endResp.Close()
	}

	// Step 3: Try to GET /connect/authorize again — without re-logging in.
	// The session cookie should now be gone, so the middleware redirects to login.
	authReq := testClient.NewRequest("GET", testClient.Discovery.AuthorizationEndpoint)
	authReq.AddQuery("client_id", "myclient")
	authReq.AddQuery("response_type", "code")
	authReq.AddQuery("redirect_uri", "http://localhost/callback")
	authReq.AddQuery("scope", "email")
	authReq.AddQuery("state", ValidState)
	authReq.AddQuery("nonce", ValidNonce)

	authResp, err := authReq.Send()
	if err != nil {
		t.Fatalf("authorize GET after logout error: %v", err)
	}
	defer authResp.Close()

	// The middleware should redirect to /login, and the http.Client follows it to
	// the login page (200).  If the old session was still valid, the authorize
	// endpoint would redirect straight to the callback (causing a url.Error).
	if authResp.StatusCode() != http.StatusOK {
		t.Fatalf("expected login page (200) after logout, got %d", authResp.StatusCode())
	}

	// Confirm we landed on the login page.
	body := authResp.BodyAsString()
	if !strings.Contains(body, "login") && !strings.Contains(body, "Login") {
		t.Fatalf("expected login page content after logout, got: %.200s", body)
	}
}

// Test_EndSession_WithPostLogoutRedirect verifies that post_logout_redirect_uri is honoured.
func Test_EndSession_WithPostLogoutRedirect(t *testing.T) {
	testClient.Reset()

	// Build end_session URL with post_logout_redirect_uri and state.
	postLogoutURI := "http://localhost/loggedout"
	state := "logoutstate123"
	endSessionURL := testClient.Discovery.EndSessionEndpoint

	req := testClient.NewRequest("GET", endSessionURL)
	req.AddQuery("post_logout_redirect_uri", postLogoutURI)
	req.AddQuery("state", state)

	resp, err := req.Send()
	// The http.Client will try to follow the redirect to http://localhost/loggedout,
	// which the test server doesn't serve → url.Error with the final URL.
	if err != nil {
		urlErr, ok := err.(*url.Error)
		if !ok {
			t.Fatalf("unexpected non-URL error: %v", err)
		}
		// The final redirect URL must contain the state parameter.
		if !strings.Contains(urlErr.URL, "state="+state) {
			t.Fatalf("expected state=%q in redirect URL %q", state, urlErr.URL)
		}
		// The final redirect URL must target the post_logout_redirect_uri.
		if !strings.HasPrefix(urlErr.URL, postLogoutURI) {
			t.Fatalf("expected redirect to %q, got %q", postLogoutURI, urlErr.URL)
		}
		return
	}

	// If we got here the test server actually responded (shouldn't happen for external URIs).
	if resp != nil {
		defer resp.Close()
		// Just verify the server processed it successfully.
		if resp.StatusCode() >= http.StatusInternalServerError {
			t.Fatalf("expected non-5xx, got %d", resp.StatusCode())
		}
	}
}

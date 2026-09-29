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

// authorizeWithSession sends an authorization request and returns true if it
// was answered with the callback (the session is active)
func authorizeWithSession(t *testing.T) bool {
	t.Helper()
	authReq := testClient.NewRequest("GET", testClient.Discovery.AuthorizationEndpoint)
	authReq.AddQuery("client_id", "myclient")
	authReq.AddQuery("response_type", "code")
	authReq.AddQuery("redirect_uri", "http://localhost/callback")
	authReq.AddQuery("scope", "email")
	authReq.AddQuery("state", ValidState)

	resp, err := authReq.Send()
	if err != nil {
		// the callback cannot be reached: the authorization succeeded
		_, ok := err.(*url.Error)
		return ok
	}
	defer resp.Close()

	return false
}

// Test_EndSession_ClearsSession verifies that the confirmed logout closes the
// session. Without id_token_hint the user must confirm it (a POST with the
// CSRF token), so a link cannot log the user out.
func Test_EndSession_ClearsSession(t *testing.T) {
	testClient.Reset()

	tc := authorizationTestCase{
		clientID:     "myclient",
		secret:       "secret",
		username:     "user",
		password:     "password",
		scope:        "openid email",
		responseType: "code",
		redirectURI:  "http://localhost/callback",
	}
	if _, callbackURL := runAuthorizationFlowAndLogin(t, tc); callbackURL == nil {
		t.Fatal("expected successful authorization flow")
	}

	// the GET only asks for confirmation
	pageResp, err := testClient.NewRequest("GET", testClient.Discovery.EndSessionEndpoint).Send()
	if err != nil {
		t.Fatalf("end_session GET error: %v", err)
	}
	if pageResp.StatusCode() != http.StatusOK {
		t.Fatalf("expected the logout confirmation page, got %d", pageResp.StatusCode())
	}
	csrf := getCSRFValue(pageResp)
	pageResp.Close()

	if !authorizeWithSession(t) {
		t.Fatal("expected the session to be active before the confirmation")
	}

	confirm := testClient.NewRequest("POST", testClient.Discovery.EndSessionEndpoint)
	confirm.AddForm("__csrf", csrf)
	confirmResp, err := confirm.Send()
	if err != nil {
		t.Fatalf("end_session POST error: %v", err)
	}
	body := confirmResp.BodyAsString()
	confirmResp.Close()
	if confirmResp.StatusCode() != http.StatusOK || !strings.Contains(body, "signed out") {
		t.Fatalf("expected the signed out page, got %d: %.200s", confirmResp.StatusCode(), body)
	}

	if authorizeWithSession(t) {
		t.Fatal("expected the session to be closed after the logout")
	}
}

// Test_EndSession_WithPostLogoutRedirect verifies that a registered
// post_logout_redirect_uri is honoured when the client is identified by the id_token_hint.
func Test_EndSession_WithPostLogoutRedirect(t *testing.T) {
	testClient.Reset()

	postLogoutURI := "http://localhost/logged-out"
	state := "logoutstate123"

	req := testClient.NewRequest("GET", testClient.Discovery.EndSessionEndpoint)
	req.AddQuery("id_token_hint", getIDToken(t, ""))
	req.AddQuery("post_logout_redirect_uri", postLogoutURI)
	req.AddQuery("state", state)

	_, err := req.Send()
	urlErr, ok := err.(*url.Error)
	if !ok {
		t.Fatalf("expected a redirect to the post_logout_redirect_uri, got %v", err)
	}

	redirect, parseErr := url.Parse(urlErr.URL)
	if parseErr != nil || !strings.HasPrefix(urlErr.URL, postLogoutURI) || redirect.Query().Get("state") != state {
		t.Fatalf("expected a redirect to %s with the state, got %q", postLogoutURI, urlErr.URL)
	}
}

// Test_EndSession_RejectsUnregisteredRedirect verifies that the logout is not an open redirect.
func Test_EndSession_RejectsUnregisteredRedirect(t *testing.T) {
	testClient.Reset()

	for name, hint := range map[string]string{"without id_token_hint": "", "with id_token_hint": getIDToken(t, "")} {
		t.Run(name, func(t *testing.T) {
			req := testClient.NewRequest("GET", testClient.Discovery.EndSessionEndpoint)
			if hint != "" {
				req.AddQuery("id_token_hint", hint)
			}
			req.AddQuery("post_logout_redirect_uri", "https://evil.example.com/")

			resp, err := req.Send()
			if err != nil {
				t.Fatalf("expected an error page, got a redirect: %v", err)
			}
			defer resp.Close()

			if resp.StatusCode() != http.StatusBadRequest {
				t.Fatalf("expected status 400, got %d", resp.StatusCode())
			}
		})
	}
}

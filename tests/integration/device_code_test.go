package integration

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

type deviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

func Test_DeviceCode_AdvertisedInDiscovery(t *testing.T) {
	found := false
	for _, gt := range testClient.Discovery.GrantTypesSupported {
		if gt == "urn:ietf:params:oauth:grant-type:device_code" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected urn:ietf:params:oauth:grant-type:device_code in grant_types_supported")
	}

	if testClient.Discovery.DeviceAuthorizationEndpoint == "" {
		t.Fatal("expected device_authorization_endpoint in discovery document")
	}
}

func Test_DeviceCode_AuthorizationRequest(t *testing.T) {
	testClient.Reset()
	dc := requestDeviceCode(t, "myclient", "secret", "openid")
	if dc.DeviceCode == "" {
		t.Fatal("expected device_code in response")
	}
	if dc.UserCode == "" {
		t.Fatal("expected user_code in response")
	}
	if dc.VerificationURI == "" {
		t.Fatal("expected verification_uri in response")
	}
	if dc.ExpiresIn == 0 {
		t.Fatal("expected expires_in > 0")
	}
	if dc.Interval == 0 {
		t.Fatal("expected interval > 0")
	}
}

func Test_DeviceCode_TokenPending(t *testing.T) {
	testClient.Reset()
	dc := requestDeviceCode(t, "myclient", "secret", "")

	// Poll immediately — should get authorization_pending
	req := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	req.AddForm("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	req.AddForm("client_id", "myclient")
	req.AddForm("device_code", dc.DeviceCode)

	resp, err := req.Send()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode() != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode())
	}

	var errResp ErrorResponse
	if err := json.Unmarshal([]byte(resp.BodyAsString()), &errResp); err != nil {
		t.Fatalf("parse error response: %v", err)
	}
	if errResp.Error != "authorization_pending" {
		t.Fatalf("expected authorization_pending, got %q", errResp.Error)
	}
}

func Test_DeviceCode_InvalidClient(t *testing.T) {
	testClient.Reset()
	req := testClient.NewRequest("POST", testClient.Discovery.DeviceAuthorizationEndpoint)
	req.SetBasicAuth("badclient", "badsecret")
	req.AddForm("scope", "openid")

	resp, err := req.Send()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode() != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode())
	}
}

func Test_DeviceCode_FullFlow(t *testing.T) {
	testClient.Reset()

	// Step 1: Request device code
	dc := requestDeviceCode(t, "myclient", "secret", "openid")

	// Step 2: Establish a user session by running the auth code login flow.
	// After login the HTTP client follows redirects to the callback URI (which
	// doesn't exist on the test server), triggering a url.Error — but the session
	// cookie is already set in the cookie jar by that point.
	establishSession(t)

	// Step 3: GET /connect/device?user_code=... (session cookie present in jar)
	devicePageResp := getDevicePage(t, dc.UserCode)
	defer devicePageResp.Close()

	if devicePageResp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200 from device page, got %d: %s", devicePageResp.StatusCode(), devicePageResp.BodyAsString())
	}

	csrf := getCSRFValue(devicePageResp)
	if csrf == "" {
		t.Fatal("expected CSRF token in device page")
	}

	// Step 4: POST /connect/device with action=approve
	approveReq := testClient.NewRequest("POST", "/connect/device")
	approveReq.AddForm("user_code", dc.UserCode)
	approveReq.AddForm("action", "approve")
	approveReq.AddForm("__csrf", csrf)

	approveResp, err := approveReq.Send()
	if err != nil {
		t.Fatalf("approve POST error: %v", err)
	}
	defer approveResp.Close()

	if approveResp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200 from approve, got %d: %s", approveResp.StatusCode(), approveResp.BodyAsString())
	}

	// Step 5: Poll the token endpoint
	pollReq := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	pollReq.AddForm("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	pollReq.AddForm("client_id", "myclient")
	pollReq.AddForm("device_code", dc.DeviceCode)

	pollResp, err := pollReq.Send()
	if err != nil {
		t.Fatalf("poll token error: %v", err)
	}
	defer pollResp.Close()

	if pollResp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200 from token poll, got %d: %s", pollResp.StatusCode(), pollResp.BodyAsString())
	}

	tokens := &TokenResponse{}
	if err := pollResp.BodyAsJSON(tokens); err != nil {
		t.Fatalf("parse token response: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Fatal("expected access_token in token response")
	}
	if tokens.IDToken == nil {
		t.Fatal("expected id_token with openid scope")
	}
}

func Test_DeviceCode_Denied(t *testing.T) {
	testClient.Reset()

	// Step 1: Request device code
	dc := requestDeviceCode(t, "myclient", "secret", "")

	// Step 2: Establish session
	establishSession(t)

	// Step 3: GET device page
	devicePageResp := getDevicePage(t, dc.UserCode)
	defer devicePageResp.Close()

	csrf := getCSRFValue(devicePageResp)

	// Step 4: POST deny
	denyReq := testClient.NewRequest("POST", "/connect/device")
	denyReq.AddForm("user_code", dc.UserCode)
	denyReq.AddForm("action", "deny")
	denyReq.AddForm("__csrf", csrf)

	denyResp, err := denyReq.Send()
	if err != nil {
		t.Fatalf("deny POST error: %v", err)
	}
	defer denyResp.Close()

	if denyResp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200 from deny, got %d", denyResp.StatusCode())
	}

	// Step 5: Poll — should get access_denied
	pollReq := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	pollReq.AddForm("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	pollReq.AddForm("client_id", "myclient")
	pollReq.AddForm("device_code", dc.DeviceCode)

	pollResp, err := pollReq.Send()
	if err != nil {
		t.Fatalf("poll token error: %v", err)
	}
	defer pollResp.Close()

	if pollResp.StatusCode() != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", pollResp.StatusCode())
	}

	var errResp ErrorResponse
	if err := json.Unmarshal([]byte(pollResp.BodyAsString()), &errResp); err != nil {
		t.Fatalf("parse error response: %v", err)
	}
	if errResp.Error != "access_denied" {
		t.Fatalf("expected access_denied, got %q", errResp.Error)
	}
}

// --- helpers ---

// requestDeviceCode POSTs to the device authorization endpoint and returns the
// parsed response.
func requestDeviceCode(t *testing.T, clientID, secret, scope string) deviceAuthorizationResponse {
	t.Helper()
	req := testClient.NewRequest("POST", testClient.Discovery.DeviceAuthorizationEndpoint)
	req.SetBasicAuth(clientID, secret)
	if scope != "" {
		req.AddForm("scope", scope)
	}

	resp, err := req.Send()
	if err != nil {
		t.Fatalf("device authorization request error: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("device authorization expected 200, got %d: %s", resp.StatusCode(), resp.BodyAsString())
	}

	var dc deviceAuthorizationResponse
	if err := json.Unmarshal([]byte(resp.BodyAsString()), &dc); err != nil {
		t.Fatalf("parse device authorization response: %v", err)
	}
	return dc
}

// establishSession runs a minimal auth code flow (without caring about the
// resulting tokens) so that the test client's cookie jar contains a valid
// session cookie. The final redirect to the non-existent callback URI triggers
// a *url.Error, which is expected and ignored.
func establishSession(t *testing.T) {
	t.Helper()
	tc := authorizationTestCase{
		clientID:     "myclient",
		secret:       "secret",
		username:     "user",
		password:     "password",
		responseType: "code",
		scope:        "openid",
		redirectURI:  "http://localhost/callback",
	}

	req := createAuthorizationRequest(tc, false)
	resp, err := req.Send()
	if err != nil {
		t.Fatalf("authorize GET error: %v", err)
	}
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected login page, got %d", resp.StatusCode())
	}

	loginReq := createLoginRequest(resp, tc.username, tc.password)
	resp.Close()

	_, postErr := loginReq.Send()
	if postErr == nil {
		// No error means no redirect to callback; unexpected for valid creds
		return
	}
	if _, ok := postErr.(*url.Error); !ok {
		t.Fatalf("unexpected error type from login: %v", postErr)
	}
	// url.Error means the redirect to callback was attempted — session is set.
}

// getDevicePage sends a GET to /connect/device with the given user_code query
// parameter. The caller is responsible for closing the response.
func getDevicePage(t *testing.T, userCode string) *ClientResponse {
	t.Helper()
	req := testClient.NewRequest("GET", "/connect/device")
	req.AddQuery("user_code", userCode)
	resp, err := req.Send()
	if err != nil {
		t.Fatalf("GET /connect/device error: %v", err)
	}
	return resp
}

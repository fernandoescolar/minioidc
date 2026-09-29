package integration

// Regression tests of the defects found in the review of the upstream
// branch before merging it: they must never come back.

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// authorizationCode logs in and returns a code of myclient
func authorizationCode(t *testing.T, scope string) string {
	t.Helper()
	testClient.Reset()
	tc := authorizationTestCase{
		clientID:     "myclient",
		username:     "user",
		password:     "password",
		scope:        scope,
		responseType: "code",
		redirectURI:  "http://localhost/callback",
	}

	_, callback := runAuthorizationFlowAndLogin(t, tc)
	if callback == nil || callback.Query().Get("code") == "" {
		t.Fatal("expected a code")
	}

	return callback.Query().Get("code")
}

// tokenRequest sends a token request; an empty clientID sends no credentials
func tokenRequest(t *testing.T, clientID, secret string, form url.Values) (int, map[string]interface{}) {
	t.Helper()
	req := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	if clientID != "" && secret != "" {
		req.SetBasicAuth(clientID, secret)
	} else if clientID != "" {
		req.AddForm("client_id", clientID)
	}
	for key, values := range form {
		for _, v := range values {
			req.AddForm(key, v)
		}
	}

	resp, err := req.Send()
	if err != nil {
		t.Fatalf("token request error: %v", err)
	}
	defer resp.Close()

	body := map[string]interface{}{}
	_ = resp.BodyAsJSON(&body)
	return resp.StatusCode(), body
}

func codeForm(code string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"http://localhost/callback"}}
}

// the code of a confidential client cannot be redeemed without its secret or by another client
func Test_Regression_CodeRequiresTheClientThatReceivedIt(t *testing.T) {
	code := authorizationCode(t, "openid")
	if status, _ := tokenRequest(t, "myclient", "", codeForm(code)); status != http.StatusUnauthorized {
		t.Fatalf("expected 401 without the client secret, got %d", status)
	}

	code = authorizationCode(t, "openid")
	if status, body := tokenRequest(t, "publicclient", "", codeForm(code)); status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("expected invalid_grant for another client, got %d %v", status, body)
	}
}

// a code can only be redeemed once, also with concurrent requests
func Test_Regression_CodeCanOnlyBeRedeemedOnce(t *testing.T) {
	code := authorizationCode(t, "openid offline_access")

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		successes int
	)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if status, _ := tokenRequest(t, "myclient", "secret", codeForm(code)); status == http.StatusOK {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("expected exactly one redemption, got %d", successes)
	}
}

// the refresh tokens can only be used by the client that received them
func Test_Regression_RefreshTokenIsBoundToTheClient(t *testing.T) {
	status, body := tokenRequest(t, "myclient", "secret", codeForm(authorizationCode(t, "openid offline_access")))
	if status != http.StatusOK {
		t.Fatalf("expected tokens, got %d %v", status, body)
	}

	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {body["refresh_token"].(string)}}
	if status, _ := tokenRequest(t, "publicclient", "", refresh); status != http.StatusBadRequest {
		t.Fatalf("expected another client to be rejected, got %d", status)
	}
}

// expires_in is in seconds and the ID token lives as long as the access token
func Test_Regression_TokenLifetimes(t *testing.T) {
	status, body := tokenRequest(t, "myclient", "secret", codeForm(authorizationCode(t, "profile openid")))
	if status != http.StatusOK {
		t.Fatalf("expected tokens, got %d %v", status, body)
	}

	if body["expires_in"] != float64(1200) {
		t.Fatalf("expected expires_in 1200 seconds, got %v", body["expires_in"])
	}

	// the ID token is issued even if openid is not the first scope
	idToken, ok := body["id_token"].(string)
	if !ok {
		t.Fatal("expected an id_token with the scope 'profile openid'")
	}

	claims := decodeJWTPayload(t, idToken)
	if lifetime := claims["exp"].(float64) - claims["iat"].(float64); lifetime != 1200 {
		t.Fatalf("expected an ID token lifetime of 1200 seconds, got %v", lifetime)
	}
}

// client_credentials with offline_access is a client error, not a 500
func Test_Regression_ClientCredentialsWithOfflineAccess(t *testing.T) {
	testClient.Reset()
	status, body := tokenRequest(t, "myclient", "secret", url.Values{"grant_type": {"client_credentials"}, "scope": {"offline_access"}})
	if status != http.StatusBadRequest || body["error"] != "invalid_scope" {
		t.Fatalf("expected invalid_scope, got %d %v", status, body)
	}
}

// introspection: active is a boolean, and the ID tokens are not access tokens
func Test_Regression_Introspection(t *testing.T) {
	testClient.Reset()
	introspect := func(token string) string {
		req := testClient.NewRequest("POST", testClient.Discovery.IntrospectionEndpoint)
		req.SetBasicAuth("myclient", "secret")
		req.AddForm("token", token)
		resp, err := req.Send()
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Close()
		return resp.BodyAsString()
	}

	if body := introspect("garbage"); !strings.Contains(body, `"active":false`) {
		t.Fatalf("expected a boolean active=false, got %s", body)
	}

	if body := introspect(getIDToken(t, "")); !strings.Contains(body, `"active":false`) {
		t.Fatalf("expected an ID token to be inactive, got %s", body)
	}
}

// userinfo works with the access tokens of the code flow and rejects the ID tokens
func Test_Regression_Userinfo(t *testing.T) {
	status, body := tokenRequest(t, "myclient", "secret", codeForm(authorizationCode(t, "openid email")))
	if status != http.StatusOK {
		t.Fatalf("expected tokens, got %d %v", status, body)
	}

	userinfo := func(token string) int {
		req := testClient.NewRequest("GET", testClient.Discovery.UserinfoEndpoint)
		req.SetHeader("Authorization", "Bearer "+token)
		resp, err := req.Send()
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Close()
		return resp.StatusCode()
	}

	if status := userinfo(body["access_token"].(string)); status != http.StatusOK {
		t.Fatalf("expected userinfo with a code flow access token, got %d", status)
	}

	if status := userinfo(body["id_token"].(string)); status != http.StatusUnauthorized {
		t.Fatalf("expected an ID token to be rejected, got %d", status)
	}
}

// prompt=none on any page is not an open redirect
func Test_Regression_PromptNoneIsNotAnOpenRedirect(t *testing.T) {
	testClient.Reset()
	req := testClient.NewRequest("GET", "/profile")
	req.AddQuery("prompt", "none")
	req.AddQuery("redirect_uri", "https://evil.example.com/x")

	resp, err := req.Send()
	if err != nil {
		t.Fatalf("expected no redirect to other sites, got %v", err)
	}
	defer resp.Close()

	if !strings.Contains(resp.URL(), "/login") {
		t.Fatalf("expected the login page, got %s", resp.URL())
	}
}

// the device codes can only be redeemed by their client, and only once
func Test_Regression_DeviceCodeIsBoundToTheClientAndUsedOnce(t *testing.T) {
	testClient.Reset()
	dc := requestDeviceCode(t, "myclient", "secret", "openid")

	// the user code is normalized: lowercase and without the dash
	establishSession(t)
	typed := strings.ToLower(strings.ReplaceAll(dc.UserCode, "-", ""))
	page := getDevicePage(t, typed)
	body := page.BodyAsString()
	page.Close()
	if !strings.Contains(body, "myclient") {
		t.Fatalf("expected the device page to show the client, got: %.300s", body)
	}

	approve := testClient.NewRequest("POST", "/connect/device")
	approve.AddForm("user_code", dc.UserCode)
	approve.AddForm("action", "approve")
	approve.AddForm("__csrf", extractInputValue(body, "__csrf"))
	approveResp, err := approve.Send()
	if err != nil {
		t.Fatal(err)
	}
	approveResp.Close()

	poll := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {dc.DeviceCode}}
	if status, body := tokenRequest(t, "publicclient", "", poll); status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("expected another client to be rejected, got %d %v", status, body)
	}

	if status, body := tokenRequest(t, "myclient", "secret", poll); status != http.StatusOK {
		t.Fatalf("expected the tokens, got %d %v", status, body)
	}

	if status, _ := tokenRequest(t, "myclient", "secret", poll); status != http.StatusBadRequest {
		t.Fatalf("expected the device code to be used only once, got %d", status)
	}
}

// the devices that poll too fast get slow_down with a longer interval (RFC 8628 section 3.5)
func Test_Regression_DeviceSlowDown(t *testing.T) {
	testClient.Reset()
	dc := requestDeviceCode(t, "myclient", "secret", "openid")
	poll := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {dc.DeviceCode}}

	if _, body := tokenRequest(t, "myclient", "secret", poll); body["error"] != "authorization_pending" {
		t.Fatalf("expected authorization_pending, got %v", body)
	}

	_, body := tokenRequest(t, "myclient", "secret", poll)
	if body["error"] != "slow_down" || !strings.Contains(body["error_description"].(string), "10") {
		t.Fatalf("expected slow_down with a 10 seconds interval, got %v", body)
	}
}

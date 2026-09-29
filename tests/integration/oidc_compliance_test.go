package integration

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// decodeJWTHeader decodes the header (first) segment of a JWT.
func decodeJWTHeader(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(parts))
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("cannot decode JWT header: %v", err)
	}
	var h map[string]interface{}
	if err := json.Unmarshal(b, &h); err != nil {
		t.Fatalf("cannot unmarshal JWT header: %v", err)
	}
	return h
}

// Test_Discovery_Values checks that the discovery document advertises the
// required values for OIDC Core compliance (OIDC Discovery §3).
func Test_Discovery_Values(t *testing.T) {
	req := testClient.NewRequest("GET", "/.well-known/openid-configuration")
	resp, err := req.Send()
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Close()

	doc := &DiscoveryResponse{}
	if err := resp.BodyAsJSON(doc); err != nil {
		t.Fatalf("cannot parse discovery: %v", err)
	}

	if doc.Issuer != fakeIssuer {
		t.Errorf("issuer: expected %q, got %q", fakeIssuer, doc.Issuer)
	}

	containsStr := func(slice []string, want string) bool {
		for _, s := range slice {
			if s == want {
				return true
			}
		}
		return false
	}

	if !containsStr(doc.SubjectTypesSupported, "public") {
		t.Errorf("subject_types_supported must contain \"public\", got %v", doc.SubjectTypesSupported)
	}
	if !containsStr(doc.IDTokenSigningAlgValuesSupported, "RS256") {
		t.Errorf("id_token_signing_alg_values_supported must contain \"RS256\", got %v", doc.IDTokenSigningAlgValuesSupported)
	}
	if !containsStr(doc.ResponseTypesSupported, "code") {
		t.Errorf("response_types_supported must contain \"code\", got %v", doc.ResponseTypesSupported)
	}
	if len(doc.TokenEndpointAuthMethodsSupported) == 0 {
		t.Error("token_endpoint_auth_methods_supported must be non-empty")
	}
}

// Test_IDToken_JWT_Header verifies the ID token's JWT header contains alg=RS256
// and a kid that is present in the JWKS (OIDC Core §10.1).
func Test_IDToken_JWT_Header(t *testing.T) {
	idToken := getIDToken(t, "")
	header := decodeJWTHeader(t, idToken)

	alg, _ := header["alg"].(string)
	if alg != "RS256" {
		t.Errorf("expected alg=RS256, got %q", alg)
	}

	kid, _ := header["kid"].(string)
	if kid == "" {
		t.Error("expected non-empty kid in JWT header")
	}

	// Fetch JWKS and collect all key IDs.
	jwksReq := testClient.NewRequest("GET", testClient.Discovery.JwksURI)
	jwksResp, err := jwksReq.Send()
	if err != nil {
		t.Fatalf("JWKS request error: %v", err)
	}
	defer jwksResp.Close()

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(jwksResp.BodyAsString()), &jwks); err != nil {
		t.Fatalf("cannot parse JWKS: %v", err)
	}

	found := false
	for _, k := range jwks.Keys {
		if k["kid"] == kid {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("id_token kid %q not found in JWKS", kid)
	}
}

// Test_Sub_Consistency verifies that the sub in the ID token equals the sub
// returned by the UserInfo endpoint (OIDC Core §5.3.2).
func Test_Sub_Consistency(t *testing.T) {
	scope := "openid profile"
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
		t.Fatalf("expected 200, got %d", resp.StatusCode())
	}

	tokens := &TokenResponse{}
	if err := resp.BodyAsJSON(tokens); err != nil {
		t.Fatalf("cannot parse token response: %v", err)
	}
	if tokens.IDToken == nil {
		t.Fatal("expected id_token")
	}

	idClaims := decodeJWTPayload(t, *tokens.IDToken)
	idSub, _ := idClaims["sub"].(string)
	if idSub == "" {
		t.Fatal("expected non-empty sub in id_token")
	}

	// UserInfo endpoint.
	uiReq := testClient.NewRequest("GET", testClient.Discovery.UserinfoEndpoint)
	uiReq.SetHeader("Authorization", "Bearer "+tokens.AccessToken)
	uiResp, err := uiReq.Send()
	if err != nil {
		t.Fatalf("userinfo error: %v", err)
	}
	defer uiResp.Close()

	if uiResp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200 from userinfo, got %d", uiResp.StatusCode())
	}

	var uiClaims map[string]interface{}
	if err := json.Unmarshal([]byte(uiResp.BodyAsString()), &uiClaims); err != nil {
		t.Fatalf("cannot parse userinfo: %v", err)
	}
	uiSub, _ := uiClaims["sub"].(string)

	if idSub != uiSub {
		t.Errorf("sub mismatch: id_token sub=%q, userinfo sub=%q", idSub, uiSub)
	}
}

// Test_TokenResponse_Headers verifies that token endpoint responses include
// the required HTTP headers (RFC 6749 §5.1).
func Test_TokenResponse_Headers(t *testing.T) {
	req := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	req.SetBasicAuth("myclient", "secret")
	req.AddForm("grant_type", "password")
	req.AddForm("username", "user")
	req.AddForm("password", "password")
	req.AddForm("scope", "openid")

	resp, err := req.Send()
	if err != nil {
		t.Fatalf("token request error: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode())
	}

	ct := resp.Header("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	cc := resp.Header("Cache-Control")
	if !strings.Contains(cc, "no-store") {
		t.Errorf("expected Cache-Control to contain no-store, got %q", cc)
	}
}

// Test_StateRoundtrip verifies that a custom state value sent in the
// authorization request is echoed unchanged in the callback URL (OIDC Core §3.1.2.1).
func Test_StateRoundtrip(t *testing.T) {
	testClient.Reset()
	customState := "unique-state-xyz-789"
	tc := authorizationTestCase{
		clientID:     "myclient",
		secret:       "secret",
		username:     "user",
		password:     "password",
		scope:        "openid email",
		responseType: "code",
		redirectURI:  "http://localhost/callback",
		state:        &customState,
	}

	_, callbackURL := runAuthorizationFlowAndLogin(t, tc)
	if callbackURL == nil {
		t.Fatal("expected callback URL from authorization flow")
	}

	gotState := callbackURL.Query().Get("state")
	if gotState != customState {
		t.Errorf("state mismatch: sent %q, got back %q", customState, gotState)
	}
}

// Test_RefreshToken_Issues_IDToken verifies that exchanging a refresh token
// while openid scope was granted returns a new id_token (OIDC Core §12.2).
func Test_RefreshToken_Issues_IDToken(t *testing.T) {
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
		t.Fatalf("expected 200 for refresh, got %d", resp.StatusCode())
	}

	tokens := &TokenResponse{}
	if err := resp.BodyAsJSON(tokens); err != nil {
		t.Fatalf("cannot parse refresh response: %v", err)
	}

	if tokens.IDToken == nil || *tokens.IDToken == "" {
		t.Fatal("expected id_token in refresh token response when openid scope granted")
	}

	idClaims := decodeJWTPayload(t, *tokens.IDToken)
	if idClaims["iss"] == nil || idClaims["sub"] == nil || idClaims["exp"] == nil {
		t.Errorf("id_token missing required claims: %v", idClaims)
	}
}

// Test_AuthTime_Claim verifies that the ID token contains a valid auth_time
// claim (OIDC Core §2).
func Test_AuthTime_Claim(t *testing.T) {
	idToken := getIDToken(t, "")
	claims := decodeJWTPayload(t, idToken)

	authTimeRaw, ok := claims["auth_time"]
	if !ok {
		t.Fatal("expected auth_time claim in id_token")
	}

	authTime, ok := authTimeRaw.(float64)
	if !ok {
		t.Fatalf("expected auth_time to be numeric, got %T", authTimeRaw)
	}
	if authTime <= 0 {
		t.Fatalf("expected auth_time > 0, got %v", authTime)
	}
	now := float64(time.Now().Unix())
	if authTime > now {
		t.Errorf("auth_time %v is in the future (now=%v)", authTime, now)
	}
	if authTime < now-60 {
		t.Errorf("auth_time %v is more than 60s in the past", authTime)
	}
}

// Test_Prompt_None_LoginRequired verifies that when no session exists and
// prompt=none is sent, the server redirects to the callback with
// error=login_required (OIDC Core §3.1.2.1).
func Test_Prompt_None_LoginRequired(t *testing.T) {
	testClient.Reset() // ensure no session cookie

	promptNone := "none"
	customState := "my-prompt-none-state"
	req := testClient.NewRequest("GET", testClient.Discovery.AuthorizationEndpoint)
	req.AddQuery("client_id", "myclient")
	req.AddQuery("response_type", "code")
	req.AddQuery("redirect_uri", "http://localhost/callback")
	req.AddQuery("scope", "openid")
	req.AddQuery("prompt", promptNone)
	req.AddQuery("state", customState)
	req.AddQuery("nonce", ValidNonce)

	_, err := req.Send()
	if err == nil {
		t.Fatal("expected redirect to callback (url.Error), got nil error")
	}

	urlErr, ok := err.(*url.Error)
	if !ok {
		t.Fatalf("expected *url.Error, got %T: %v", err, err)
	}

	u, parseErr := url.ParseRequestURI(urlErr.URL)
	if parseErr != nil {
		t.Fatalf("cannot parse callback URL %q: %v", urlErr.URL, parseErr)
	}

	if errParam := u.Query().Get("error"); errParam != "login_required" {
		t.Errorf("expected error=login_required, got %q", errParam)
	}
	if stateParam := u.Query().Get("state"); stateParam != customState {
		t.Errorf("expected state=%q, got %q", customState, stateParam)
	}
}

// Test_MaxAge_ForcesReauth verifies that max_age=0 forces re-authentication
// even when a valid session cookie is present (OIDC Core §3.1.2.1).
func Test_MaxAge_ForcesReauth(t *testing.T) {
	testClient.Reset()

	// Step 1: establish a session by completing a normal authorization flow.
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
		t.Fatal("expected successful authorization flow to establish session")
	}

	// Step 2: make a new authorize request with max_age=0 using the same client
	// (session cookie is in the jar). The server must expire the session and
	// redirect back to the login page.
	maxAge := fmt.Sprintf("%d", 0)
	req := testClient.NewRequest("GET", testClient.Discovery.AuthorizationEndpoint)
	req.AddQuery("client_id", "myclient")
	req.AddQuery("response_type", "code")
	req.AddQuery("redirect_uri", "http://localhost/callback")
	req.AddQuery("scope", "openid email")
	req.AddQuery("state", ValidState)
	req.AddQuery("nonce", ValidNonce)
	req.AddQuery("max_age", maxAge)

	resp, err := req.Send()
	if err != nil {
		t.Fatalf("unexpected error with max_age=0: %v", err)
	}
	defer resp.Close()

	// The server must redirect to login and the http client follows to the login
	// form — expecting a 200 HTML login page.
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200 (login page), got %d", resp.StatusCode())
	}
	body := resp.BodyAsString()
	if !strings.Contains(body, "username") {
		t.Error("expected login form in response body (containing 'username')")
	}
}

// Test_Scope_In_Token_Response verifies that the token response includes the
// granted scope (RFC 6749 §5.1).
func Test_Scope_In_Token_Response(t *testing.T) {
	req := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	req.SetBasicAuth("myclient", "secret")
	req.AddForm("grant_type", "password")
	req.AddForm("username", "user")
	req.AddForm("password", "password")
	req.AddForm("scope", "openid email")

	resp, err := req.Send()
	if err != nil {
		t.Fatalf("token request error: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode())
	}

	tokens := &TokenResponse{}
	if err := resp.BodyAsJSON(tokens); err != nil {
		t.Fatalf("cannot parse token response: %v", err)
	}

	if tokens.Scope == nil || *tokens.Scope == "" {
		t.Fatal("expected non-empty scope in token response")
	}

	scopeParts := strings.Fields(*tokens.Scope)
	containsScope := func(s string) bool {
		for _, p := range scopeParts {
			if p == s {
				return true
			}
		}
		return false
	}
	if !containsScope("openid") {
		t.Errorf("expected scope to contain \"openid\", got %q", *tokens.Scope)
	}
	if !containsScope("email") {
		t.Errorf("expected scope to contain \"email\", got %q", *tokens.Scope)
	}
}

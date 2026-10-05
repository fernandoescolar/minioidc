package api_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/api"
	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const (
	issuer         = "http://issuer.test/"
	audience       = "http://api.test"
	redirectURI    = "http://client.test/callback"
	redirectURI2   = "http://client.test/other-callback"
	postLogoutURI  = "http://client.test/logged-out"
	clientID       = "confidential"
	clientSecret   = "client-secret"
	otherClientID  = "other"
	publicClientID = "public"
	username       = "user"
	password       = "password"
	codeVerifier   = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

var (
	csrfRegex   = regexp.MustCompile(`name="__csrf" value="([^"]+)"`)
	mfaIVRegex  = regexp.MustCompile(`name="verification_iv" value="([^"]+)"`)
	hashesOnce  sync.Once
	secretHash  string
	passwdHash  string
	codeChallng = challenge(codeVerifier)
)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type testServer struct {
	*httptest.Server
	minioidc *api.Minioidc
	clock    *clock
	issuer   string
	// base is the path of the issuer, where the endpoints are published
	base string
}

func newTestServer(t *testing.T, requireMFA bool, options ...func(*api.Builder)) *testServer {
	t.Helper()
	hashesOnce.Do(func() {
		secretHash = hash(t, clientSecret)
		passwdHash = hash(t, password)
	})

	builder := &api.Builder{
		Issuer:                          issuer,
		Audience:                        audience,
		MasterKey:                       "0123456789abcdefghijklmnopqrstuvwxyz",
		RequireMFA:                      requireMFA,
		BaseTemplateFilepath:            "../../templates/base.html",
		LoginTemplateFilepath:           "../../templates/login.html",
		MFACreateTemplateFilepath:       "../../templates/mfa_create.html",
		MFAVerifyTemplateFilepath:       "../../templates/mfa_verify.html",
		LogoutTemplateFilepath:          "../../templates/logout.html",
		DeviceTemplateFilepath:          "../../templates/device.html",
		ErrorTemplateFilepath:           "../../templates/error.html",
		ProfileTemplateFilepath:         "../../templates/profile.html",
		ProfilePasswordTemplateFilepath: "../../templates/profile_password.html",
		ProfileMFATemplateFilepath:      "../../templates/profile_mfa.html",
		SetupTemplateFilepath:           "../../templates/setup.html",
		ProfilePasskeysTemplateFilepath: "../../templates/profile_passkeys.html",
		ResetPasswordTemplateFilepath:   "../../templates/reset_password.html",
		Clients: []api.Client{
			{ID: clientID, SecretHash: secretHash, RedirectURIs: []string{redirectURI, redirectURI2}, PostLogoutRedirectURIs: []string{postLogoutURI}},
			{ID: otherClientID, SecretHash: secretHash, RedirectURIs: []string{redirectURI}},
			{ID: publicClientID, RedirectURIs: []string{redirectURI}},
		},
		Users: []api.User{
			{Subject: "1", Email: "user@mail.test", PreferredUsername: username, PasswordHash: passwdHash, Address: "1 Main St", Phone: "+34600000000", Name: "Test User", GivenName: "Test", FamilyName: "User"},
			{Subject: "2", Email: "other@mail.test", EmailVerified: true, PreferredUsername: "other", PasswordHash: passwdHash},
		},
	}

	for _, option := range options {
		option(builder)
	}

	m, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	c := &clock{now: time.Now()}
	m.Now = c.Now
	server := httptest.NewServer(m.Handler())
	t.Cleanup(func() {
		server.Close()
		m.Close()
	})

	base := strings.TrimSuffix(strings.TrimPrefix(builder.Issuer, "http://issuer.test"), "/")
	return &testServer{Server: server, minioidc: m, clock: c, issuer: builder.Issuer, base: base}
}

func hash(t *testing.T, value string) string {
	h, err := bcrypt.GenerateFromPassword([]byte(value), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// browser is an HTTP client with cookies that does not follow redirects
func browser(t *testing.T) *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	return &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (s *testServer) url(path string) string {
	return s.URL + s.base + path
}

func authorizePath(clientID string, extra url.Values) string {
	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("response_type", "code")
	params.Set("scope", "openid profile email offline_access")
	params.Set("redirect_uri", redirectURI)
	params.Set("state", "state-123")
	params.Set("nonce", "nonce-123")
	params.Set("code_challenge", codeChallng)
	params.Set("code_challenge_method", "S256")
	for k, v := range extra {
		params[k] = v
	}

	return "/connect/authorize?" + params.Encode()
}

func do(t *testing.T, c *http.Client, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	return resp, string(body)
}

func get(t *testing.T, c *http.Client, u string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	return do(t, c, req)
}

func postForm(t *testing.T, c *http.Client, u string, form url.Values, setup ...func(*http.Request)) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	for _, s := range setup {
		s(req)
	}
	return do(t, c, req)
}

func basicAuth(id, secret string) func(*http.Request) {
	return func(r *http.Request) { r.SetBasicAuth(id, secret) }
}

func expectStatus(t *testing.T, resp *http.Response, body string, status int) {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("Expected status %d, got %d: %s", status, resp.StatusCode, body)
	}
}

func expectError(t *testing.T, resp *http.Response, body string, status int, oauthError string) {
	t.Helper()
	expectStatus(t, resp, body, status)
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &e); err != nil || e.Error != oauthError {
		t.Fatalf("Expected error %s, got %s", oauthError, body)
	}
}

func (s *testServer) resolve(t *testing.T, resp *http.Response) string {
	t.Helper()
	location, err := resp.Location()
	if err != nil {
		t.Fatalf("Expected a redirect, got %d", resp.StatusCode)
	}

	if location.Host == "client.test" {
		return location.String()
	}

	return s.URL + location.RequestURI()
}

// login submits the login form of the given login page URL
func (s *testServer) login(t *testing.T, c *http.Client, loginURL, user, pass string) (*http.Response, string) {
	t.Helper()
	resp, body := get(t, c, loginURL)
	expectStatus(t, resp, body, http.StatusOK)

	csrf := csrfRegex.FindStringSubmatch(body)
	if csrf == nil {
		t.Fatalf("CSRF token not found in: %s", body)
	}

	return postForm(t, c, loginURL, url.Values{"username": {user}, "password": {pass}, "__csrf": {csrf[1]}})
}

// authorize runs the authorization request (logging in if needed) and returns the code
func (s *testServer) authorize(t *testing.T, c *http.Client, path string) string {
	t.Helper()
	resp, body := get(t, c, s.url(path))
	if resp.StatusCode == http.StatusFound && strings.HasPrefix(resp.Header.Get("Location"), s.base+"/login") {
		resp, body = s.login(t, c, s.resolve(t, resp), username, password)
		expectStatus(t, resp, body, http.StatusFound)
		resp, body = get(t, c, s.resolve(t, resp))
	}

	expectStatus(t, resp, body, http.StatusFound)
	callback, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || callback.Host != "client.test" {
		t.Fatalf("Expected redirect to the client, got %s", resp.Header.Get("Location"))
	}

	if callback.Query().Get("state") != "state-123" || callback.Query().Get("iss") != s.issuer {
		t.Fatalf("Expected state and iss in the callback: %s", callback)
	}

	return callback.Query().Get("code")
}

type tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

func (s *testServer) exchangeCode(t *testing.T, code string) tokens {
	t.Helper()
	resp, body := postForm(t, http.DefaultClient, s.url("/connect/token"), url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
	}, basicAuth(clientID, clientSecret))
	expectStatus(t, resp, body, http.StatusOK)

	var tk tokens
	if err := json.Unmarshal([]byte(body), &tk); err != nil {
		t.Fatal(err)
	}

	return tk
}

func (s *testServer) refresh(c *http.Client, t *testing.T, refreshToken string) (*http.Response, string) {
	t.Helper()
	return postForm(t, c, s.url("/connect/token"), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	})
}

func (s *testServer) userinfo(t *testing.T, accessToken string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, s.url("/connect/userinfo"), nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	return do(t, http.DefaultClient, req)
}

func TestAuthorizationCodeFlow(t *testing.T) {
	s := newTestServer(t, false)
	c := browser(t)

	code := s.authorize(t, c, authorizePath(clientID, nil))
	tk := s.exchangeCode(t, code)

	if tk.ExpiresIn != 20*60 || tk.TokenType != "Bearer" {
		t.Errorf("Unexpected token response: %+v", tk)
	}

	idToken := &domain.IDTokenClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(tk.IDToken, idToken); err != nil {
		t.Fatal(err)
	}
	if len(idToken.Audience) != 1 || idToken.Audience[0] != clientID || idToken.AuthorizedParty != clientID {
		t.Errorf("Expected the client as ID token audience: %+v", idToken.Audience)
	}
	if idToken.Nonce != "nonce-123" || idToken.AccessTokenHash == "" || idToken.AuthTime == 0 || idToken.SessionID == "" {
		t.Errorf("Missing ID token claims: %+v", idToken)
	}

	// the code can only be used once, and reusing it revokes the refresh tokens issued with it
	resp, body := postForm(t, http.DefaultClient, s.url("/connect/token"), url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {codeVerifier},
	}, basicAuth(clientID, clientSecret))
	expectError(t, resp, body, http.StatusBadRequest, "invalid_grant")
	resp, body = s.refresh(http.DefaultClient, t, tk.RefreshToken)
	expectError(t, resp, body, http.StatusBadRequest, "invalid_grant")

	tk = s.exchangeCode(t, s.authorize(t, c, authorizePath(clientID, nil)))

	resp, body = s.userinfo(t, tk.AccessToken)
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, `"sub":"1"`) || !strings.Contains(body, "user@mail.test") || strings.Contains(body, "address") || strings.Contains(body, "phone_number") {
		t.Errorf("Unexpected userinfo: %s", body)
	}

	// the ID token is not an access token
	resp, body = s.userinfo(t, tk.IDToken)
	expectError(t, resp, body, http.StatusUnauthorized, "invalid_token")

	// refresh tokens rotate
	resp, body = s.refresh(http.DefaultClient, t, tk.RefreshToken)
	expectStatus(t, resp, body, http.StatusOK)
	var refreshed tokens
	_ = json.Unmarshal([]byte(body), &refreshed)

	resp, body = s.refresh(http.DefaultClient, t, tk.RefreshToken)
	expectError(t, resp, body, http.StatusBadRequest, "invalid_grant")

	resp, body = s.userinfo(t, refreshed.AccessToken)
	expectStatus(t, resp, body, http.StatusOK)

	// revocation
	resp, body = postForm(t, http.DefaultClient, s.url("/connect/revoke"), url.Values{"token": {refreshed.RefreshToken}}, basicAuth(clientID, clientSecret))
	expectStatus(t, resp, body, http.StatusOK)
	resp, body = s.refresh(http.DefaultClient, t, refreshed.RefreshToken)
	expectError(t, resp, body, http.StatusBadRequest, "invalid_grant")

	// RP-initiated logout closes the session and revokes the access tokens
	logout := url.Values{"id_token_hint": {tk.IDToken}, "post_logout_redirect_uri": {postLogoutURI}, "state": {"bye"}}
	resp, body = get(t, c, s.url("/connect/endsession?"+logout.Encode()))
	expectStatus(t, resp, body, http.StatusFound)
	if resp.Header.Get("Location") != postLogoutURI+"?state=bye" {
		t.Errorf("Unexpected logout redirect: %s", resp.Header.Get("Location"))
	}

	resp, body = s.userinfo(t, refreshed.AccessToken)
	expectError(t, resp, body, http.StatusUnauthorized, "invalid_token")

	resp, _ = get(t, c, s.url(authorizePath(clientID, nil)))
	if !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
		t.Errorf("Expected to login again after logout")
	}
}

func TestAuthorizationCodeFlowWithSQLite(t *testing.T) {
	s := newTestServer(t, false, func(b *api.Builder) {
		b.UseSQLite(t.TempDir()+"/minioidc.sqlite3", api.All)
	})
	c := browser(t)

	code := s.authorize(t, c, authorizePath(clientID, nil))
	tk := s.exchangeCode(t, code)

	resp, body := postForm(t, http.DefaultClient, s.url("/connect/token"), url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {codeVerifier},
	}, basicAuth(clientID, clientSecret))
	expectError(t, resp, body, http.StatusBadRequest, "invalid_grant")
	resp, body = s.refresh(http.DefaultClient, t, tk.RefreshToken)
	expectError(t, resp, body, http.StatusBadRequest, "invalid_grant")

	tk = s.exchangeCode(t, s.authorize(t, c, authorizePath(clientID, nil)))
	resp, body = s.userinfo(t, tk.AccessToken)
	expectStatus(t, resp, body, http.StatusOK)

	resp, body = s.refresh(http.DefaultClient, t, tk.RefreshToken)
	expectStatus(t, resp, body, http.StatusOK)
	var refreshed tokens
	_ = json.Unmarshal([]byte(body), &refreshed)

	// replaying a rotated refresh token revokes the whole family
	resp, body = s.refresh(http.DefaultClient, t, tk.RefreshToken)
	expectError(t, resp, body, http.StatusBadRequest, "invalid_grant")
	resp, body = s.refresh(http.DefaultClient, t, refreshed.RefreshToken)
	expectError(t, resp, body, http.StatusBadRequest, "invalid_grant")

	resp, body = get(t, c, s.url("/connect/endsession?"+url.Values{"id_token_hint": {tk.IDToken}}.Encode()))
	expectStatus(t, resp, body, http.StatusOK)
	resp, body = s.userinfo(t, tk.AccessToken)
	expectError(t, resp, body, http.StatusUnauthorized, "invalid_token")
}

func TestLogoutRejectsUnregisteredRedirect(t *testing.T) {
	s := newTestServer(t, false)
	c := browser(t)
	tk := s.exchangeCode(t, s.authorize(t, c, authorizePath(clientID, nil)))

	logout := url.Values{"id_token_hint": {tk.IDToken}, "post_logout_redirect_uri": {"https://evil.test"}}
	resp, body := get(t, c, s.url("/connect/endsession?"+logout.Encode()))
	expectError(t, resp, body, http.StatusBadRequest, "invalid_request")

	// without id_token_hint the user must confirm
	resp, body = get(t, c, s.url("/connect/endsession"))
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, "Do you want to sign out?") {
		t.Errorf("Expected logout confirmation: %s", body)
	}
}

// expectAuthorizeError checks the authorization error is redirected to the client
func expectAuthorizeError(t *testing.T, resp *http.Response, oauthError string) {
	t.Helper()
	location, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || err != nil || !strings.HasPrefix(location.String(), redirectURI) {
		t.Fatalf("Expected redirect to the client, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	params := responseParams(location)
	if params.Get("error") != oauthError || params.Get("state") != "state-123" || params.Get("code") != "" {
		t.Fatalf("Expected error %s with state, got %s", oauthError, location)
	}
}

func TestAddressAndPhoneScopes(t *testing.T) {
	s := newTestServer(t, false)
	code := s.authorize(t, browser(t), authorizePath(clientID, url.Values{"scope": {"openid address phone"}}))
	tk := s.exchangeCode(t, code)

	resp, body := s.userinfo(t, tk.AccessToken)
	expectStatus(t, resp, body, http.StatusOK)
	for _, expected := range []string{`"address":{"formatted":"1 Main St"}`, `"phone_number":"+34600000000"`} {
		if !strings.Contains(body, expected) {
			t.Errorf("Expected %s in userinfo: %s", expected, body)
		}
	}

	if strings.Contains(body, "email") || strings.Contains(body, "preferred_username") {
		t.Errorf("Expected only the claims of the requested scopes: %s", body)
	}

	idToken := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(tk.IDToken, idToken); err != nil {
		t.Fatal(err)
	}
	if idToken["phone_number"] != "+34600000000" || idToken["address"] == nil {
		t.Errorf("Expected address and phone in the ID token: %v", idToken)
	}
}

func TestAuthorizeErrors(t *testing.T) {
	s := newTestServer(t, false)
	c := browser(t)
	s.authorize(t, c, authorizePath(clientID, nil)) // login

	// errors about the client or the redirect_uri are never redirected
	resp, body := get(t, c, s.url(authorizePath(clientID, url.Values{"redirect_uri": {"https://evil.test/callback"}})))
	expectError(t, resp, body, http.StatusBadRequest, "invalid_request")

	resp, body = get(t, c, s.url(authorizePath("unknown", nil)))
	expectError(t, resp, body, http.StatusBadRequest, "invalid_client")

	// the rest are redirected to the client with the state
	resp, _ = get(t, c, s.url(authorizePath(clientID, url.Values{"scope": {"openid admin"}})))
	expectAuthorizeError(t, resp, "invalid_scope")

	resp, _ = get(t, c, s.url(authorizePath(clientID, url.Values{"response_type": {"token"}})))
	expectAuthorizeError(t, resp, "unsupported_response_type")
}

func TestTokenRequiresTheAuthorizationRedirectURI(t *testing.T) {
	s := newTestServer(t, false)
	code := s.authorize(t, browser(t), authorizePath(clientID, url.Values{"redirect_uri": {redirectURI2}}))

	// redirectURI is registered, but it is not the one of the authorization request
	resp, body := postForm(t, http.DefaultClient, s.url("/connect/token"), url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {codeVerifier},
	}, basicAuth(clientID, clientSecret))
	expectError(t, resp, body, http.StatusBadRequest, "invalid_grant")
}

func TestTokenRequiresClientAuthentication(t *testing.T) {
	s := newTestServer(t, false)
	code := s.authorize(t, browser(t), authorizePath(clientID, nil))
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {codeVerifier}}

	resp, body := postForm(t, http.DefaultClient, s.url("/connect/token"), form, basicAuth(clientID, "wrong"))
	expectError(t, resp, body, http.StatusUnauthorized, "invalid_client")

	resp, body = postForm(t, http.DefaultClient, s.url("/connect/token"), form)
	expectError(t, resp, body, http.StatusUnauthorized, "invalid_client")

	// a code issued to a client cannot be used by another client
	resp, body = postForm(t, http.DefaultClient, s.url("/connect/token"), form, basicAuth(otherClientID, clientSecret))
	expectError(t, resp, body, http.StatusBadRequest, "invalid_grant")
}

func TestPublicClientRequiresPKCE(t *testing.T) {
	s := newTestServer(t, false)
	c := browser(t)
	s.authorize(t, c, authorizePath(publicClientID, nil)) // login

	resp, _ := get(t, c, s.url(authorizePath(publicClientID, url.Values{"code_challenge": {""}, "code_challenge_method": {""}})))
	expectAuthorizeError(t, resp, "invalid_request")

	resp, _ = get(t, c, s.url(authorizePath(publicClientID, url.Values{"code_challenge_method": {"plain"}})))
	expectAuthorizeError(t, resp, "invalid_request")

	var body string

	code := s.authorize(t, c, authorizePath(publicClientID, nil))
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "client_id": {publicClientID}}

	wrong := url.Values{}
	for k, v := range form {
		wrong[k] = v
	}
	wrong.Set("code_verifier", strings.Repeat("a", 43))
	resp, body = postForm(t, http.DefaultClient, s.url("/connect/token"), wrong)
	expectError(t, resp, body, http.StatusBadRequest, "invalid_grant")

	// the failed attempt consumed the code
	form.Set("code_verifier", codeVerifier)
	resp, body = postForm(t, http.DefaultClient, s.url("/connect/token"), form)
	expectError(t, resp, body, http.StatusBadRequest, "invalid_grant")

	code = s.authorize(t, c, authorizePath(publicClientID, nil))
	form.Set("code", code)
	resp, body = postForm(t, http.DefaultClient, s.url("/connect/token"), form)
	expectStatus(t, resp, body, http.StatusOK)
}

func TestExpiredCode(t *testing.T) {
	s := newTestServer(t, false)
	code := s.authorize(t, browser(t), authorizePath(clientID, nil))

	s.clock.Advance(6 * time.Minute)
	resp, body := postForm(t, http.DefaultClient, s.url("/connect/token"), url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {codeVerifier},
	}, basicAuth(clientID, clientSecret))
	expectError(t, resp, body, http.StatusBadRequest, "invalid_grant")
}

func TestLoginLockout(t *testing.T) {
	s := newTestServer(t, false)
	c := browser(t)
	loginURL := s.url("/login")

	for i := 0; i < 4; i++ {
		_, body := s.login(t, c, loginURL, username, "wrong")
		if !strings.Contains(body, "Invalid login") {
			t.Fatalf("Expected invalid login: %s", body)
		}
	}

	_, body := s.login(t, c, loginURL, username, "wrong")
	if !strings.Contains(body, "Too many failed attempts") {
		t.Fatalf("Expected the user to be blocked: %s", body)
	}

	// the right password does not work (nor is revealed) while blocked
	resp, body := s.login(t, c, loginURL, username, password)
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, "Too many failed attempts") {
		t.Fatalf("Expected the user to be blocked: %s", body)
	}

	s.clock.Advance(16 * time.Minute)
	resp, body = s.login(t, c, loginURL, username, password)
	expectStatus(t, resp, body, http.StatusFound)
}

func TestLoginDoesNotRedirectToOtherSites(t *testing.T) {
	s := newTestServer(t, false)
	for _, returnURL := range []string{"https://evil.test", "//evil.test", "/\\evil.test", "javascript:alert(1)"} {
		resp, body := s.login(t, browser(t), s.url("/login?return_url="+url.QueryEscape(returnURL)), username, password)
		expectStatus(t, resp, body, http.StatusFound)
		if resp.Header.Get("Location") != "/" {
			t.Errorf("Expected redirect to / for %s, got %s", returnURL, resp.Header.Get("Location"))
		}
	}
}

func TestMFACannotBeBypassedWithANewEnrollment(t *testing.T) {
	s := newTestServer(t, true)
	c := browser(t)

	// first login: the user enrolls a TOTP authenticator
	resp, _ := get(t, c, s.url(authorizePath(clientID, nil)))
	resp, body := s.login(t, c, s.resolve(t, resp), username, password)
	expectStatus(t, resp, body, http.StatusFound)
	resp, body = get(t, c, s.resolve(t, resp))
	expectStatus(t, resp, body, http.StatusFound)
	if !strings.HasPrefix(resp.Header.Get("Location"), "/mfa/verify") {
		t.Fatalf("Expected MFA verification, got %s", resp.Header.Get("Location"))
	}

	// the user has no MFA yet: verify redirects to the enrollment
	resp, body = get(t, c, s.resolve(t, resp))
	expectStatus(t, resp, body, http.StatusFound)
	if !strings.HasPrefix(resp.Header.Get("Location"), "/mfa/create") {
		t.Fatalf("Expected MFA enrollment, got %s", resp.Header.Get("Location"))
	}

	createURL := s.resolve(t, resp)
	resp, body = get(t, c, createURL)
	expectStatus(t, resp, body, http.StatusOK)
	secret := mfaIVRegex.FindStringSubmatch(body)[1]
	totpCode, _ := totp.GenerateCode(secret, s.clock.Now())
	resp, body = postForm(t, c, createURL, url.Values{
		"verification_iv": {secret}, "verification_code": {totpCode}, "__csrf": {csrfRegex.FindStringSubmatch(body)[1]},
	})
	expectStatus(t, resp, body, http.StatusFound)
	resp, body = get(t, c, s.resolve(t, resp))
	expectStatus(t, resp, body, http.StatusFound)
	if !strings.HasPrefix(resp.Header.Get("Location"), redirectURI) {
		t.Fatalf("Expected redirect to the client, got %s", resp.Header.Get("Location"))
	}

	callback, _ := url.Parse(resp.Header.Get("Location"))
	tk := s.exchangeCode(t, callback.Query().Get("code"))
	idToken := &domain.IDTokenClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(tk.IDToken, idToken); err != nil {
		t.Fatal(err)
	}
	if strings.Join(idToken.AuthMethods, " ") != "pwd otp mfa" {
		t.Errorf("Expected amr with MFA, got %v", idToken.AuthMethods)
	}

	// second login (e.g. an attacker with the password): enrolling another
	// authenticator must not be possible
	attacker := browser(t)
	resp, _ = get(t, attacker, s.url(authorizePath(clientID, nil)))
	resp, body = s.login(t, attacker, s.resolve(t, resp), username, password)
	expectStatus(t, resp, body, http.StatusFound)
	resp, _ = get(t, attacker, s.resolve(t, resp))
	if !strings.HasPrefix(resp.Header.Get("Location"), "/mfa/verify") {
		t.Fatalf("Expected MFA verification, got %s", resp.Header.Get("Location"))
	}

	resp, _ = get(t, attacker, s.url("/mfa/create"))
	expectStatus(t, resp, "", http.StatusFound)
	if !strings.HasPrefix(resp.Header.Get("Location"), "/mfa/verify") {
		t.Fatalf("Expected redirect to MFA verification, got %s", resp.Header.Get("Location"))
	}
}

func TestDiscoveryAndHealth(t *testing.T) {
	s := newTestServer(t, false)

	resp, body := get(t, http.DefaultClient, s.url("/.well-known/openid-configuration"))
	expectStatus(t, resp, body, http.StatusOK)
	for _, expected := range []string{`"end_session_endpoint":"http://issuer.test/connect/endsession"`, `"revocation_endpoint":"http://issuer.test/connect/revoke"`, `"code_challenge_methods_supported":["S256"]`} {
		if !strings.Contains(body, expected) {
			t.Errorf("Expected %s in discovery: %s", expected, body)
		}
	}

	resp, body = get(t, http.DefaultClient, s.url("/.well-known/jwks.json"))
	expectStatus(t, resp, body, http.StatusOK)

	resp, body = get(t, browser(t), s.url("/healthz"))
	expectStatus(t, resp, body, http.StatusOK)
}

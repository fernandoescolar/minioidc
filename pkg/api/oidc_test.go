package api_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/api"
	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/golang-jwt/jwt/v5"
)

// callbackParams returns the parameters of a redirect to the client
func callbackParams(t *testing.T, resp *http.Response) url.Values {
	t.Helper()
	location, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || err != nil || !strings.HasPrefix(location.String(), redirectURI) {
		t.Fatalf("Expected redirect to the client, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	return location.Query()
}

func expectCallbackError(t *testing.T, resp *http.Response, oauthError string) {
	t.Helper()
	params := callbackParams(t, resp)
	if params.Get("error") != oauthError || params.Get("state") != "state-123" || params.Get("iss") != issuer || params.Get("code") != "" {
		t.Fatalf("Expected error %s with state and iss, got %v", oauthError, params)
	}
}

func expectLoginRedirect(t *testing.T, resp *http.Response) *url.URL {
	t.Helper()
	location, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || err != nil || location.Path != "/login" {
		t.Fatalf("Expected redirect to the login, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	return location
}

func parseIDToken(t *testing.T, idToken string) *domain.IDTokenClaims {
	t.Helper()
	claims := &domain.IDTokenClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(idToken, claims); err != nil {
		t.Fatal(err)
	}

	return claims
}

func TestPromptNone(t *testing.T) {
	s := newTestServer(t, false)
	c := browser(t)

	resp, _ := get(t, c, s.url(authorizePath(clientID, url.Values{"prompt": {"none"}})))
	expectCallbackError(t, resp, "login_required")

	resp, _ = get(t, c, s.url(authorizePath(clientID, url.Values{"prompt": {"none login"}})))
	expectCallbackError(t, resp, "invalid_request")

	s.authorize(t, c, authorizePath(clientID, nil)) // login
	resp, _ = get(t, c, s.url(authorizePath(clientID, url.Values{"prompt": {"none"}})))
	if callbackParams(t, resp).Get("code") == "" {
		t.Fatal("Expected a code with an active session")
	}
}

func TestPromptNoneWithPendingMFA(t *testing.T) {
	s := newTestServer(t, true)
	c := browser(t)

	resp, body := s.login(t, c, s.url("/login"), username, password)
	expectStatus(t, resp, body, http.StatusFound)

	resp, _ = get(t, c, s.url(authorizePath(clientID, url.Values{"prompt": {"none"}})))
	expectCallbackError(t, resp, "interaction_required")
}

func TestPromptLoginForcesANewLogin(t *testing.T) {
	s := newTestServer(t, false)
	c := browser(t)
	first := parseIDToken(t, s.exchangeCode(t, s.authorize(t, c, authorizePath(clientID, nil))).IDToken)

	s.clock.Advance(time.Minute)
	for _, prompt := range []string{"login", "select_account"} {
		resp, _ := get(t, c, s.url(authorizePath(clientID, url.Values{"prompt": {prompt}})))
		login := expectLoginRedirect(t, resp)

		// after the login, the request must not ask for a login again
		returnURL := login.Query().Get("return_url")
		if strings.Contains(returnURL, "prompt") {
			t.Fatalf("Expected the prompt to be removed from the return url: %s", returnURL)
		}
	}

	code := s.authorize(t, c, authorizePath(clientID, url.Values{"prompt": {"login"}}))
	second := parseIDToken(t, s.exchangeCode(t, code).IDToken)
	if second.AuthTime <= first.AuthTime {
		t.Errorf("Expected a newer auth_time: %d <= %d", second.AuthTime, first.AuthTime)
	}

	// consent is implicit
	resp, _ := get(t, c, s.url(authorizePath(clientID, url.Values{"prompt": {"consent"}})))
	if callbackParams(t, resp).Get("code") == "" {
		t.Fatal("Expected a code with prompt=consent")
	}
}

func TestMaxAge(t *testing.T) {
	s := newTestServer(t, false)
	c := browser(t)
	s.authorize(t, c, authorizePath(clientID, nil)) // login
	s.clock.Advance(2 * time.Minute)

	resp, _ := get(t, c, s.url(authorizePath(clientID, url.Values{"max_age": {"600"}})))
	if callbackParams(t, resp).Get("code") == "" {
		t.Fatal("Expected a code with a recent login")
	}

	resp, _ = get(t, c, s.url(authorizePath(clientID, url.Values{"max_age": {"60"}})))
	login := expectLoginRedirect(t, resp)
	if strings.Contains(login.Query().Get("return_url"), "max_age") {
		t.Fatal("Expected max_age to be removed from the return url")
	}

	resp, _ = get(t, c, s.url(authorizePath(clientID, url.Values{"max_age": {"60"}, "prompt": {"none"}})))
	expectCallbackError(t, resp, "login_required")

	resp, _ = get(t, c, s.url(authorizePath(clientID, url.Values{"max_age": {"-1"}})))
	expectCallbackError(t, resp, "invalid_request")
}

func TestIDTokenHintInAuthorization(t *testing.T) {
	s := newTestServer(t, false)
	user1 := s.exchangeCode(t, s.authorize(t, browser(t), authorizePath(clientID, nil))).IDToken

	// the same user
	c := browser(t)
	s.authorize(t, c, authorizePath(clientID, nil))
	resp, _ := get(t, c, s.url(authorizePath(clientID, url.Values{"prompt": {"none"}, "id_token_hint": {user1}})))
	if callbackParams(t, resp).Get("code") == "" {
		t.Fatal("Expected a code for the hinted user")
	}

	// another user is logged in
	other := browser(t)
	resp, _ = get(t, other, s.url(authorizePath(clientID, nil)))
	resp, body := s.login(t, other, s.resolve(t, resp), "other", password)
	expectStatus(t, resp, body, http.StatusFound)

	resp, _ = get(t, other, s.url(authorizePath(clientID, url.Values{"prompt": {"none"}, "id_token_hint": {user1}})))
	expectCallbackError(t, resp, "login_required")

	resp, _ = get(t, other, s.url(authorizePath(clientID, url.Values{"id_token_hint": {user1}})))
	expectLoginRedirect(t, resp)

	resp, _ = get(t, other, s.url(authorizePath(clientID, url.Values{"id_token_hint": {"not-a-token"}})))
	expectCallbackError(t, resp, "invalid_request")
}

func TestUnsupportedAuthorizationParameters(t *testing.T) {
	s := newTestServer(t, false)
	c := browser(t)

	resp, _ := get(t, c, s.url(authorizePath(clientID, url.Values{"request": {"eyJhbGciOiJub25lIn0.e30."}})))
	expectCallbackError(t, resp, "request_not_supported")

	resp, _ = get(t, c, s.url(authorizePath(clientID, url.Values{"request_uri": {"https://client.test/request.jwt"}})))
	expectCallbackError(t, resp, "request_uri_not_supported")

	resp, _ = get(t, c, s.url(authorizePath(clientID, url.Values{"response_mode": {"fragment"}})))
	expectCallbackError(t, resp, "invalid_request")

	// optional parameters are accepted and ignored
	optional := url.Values{
		"display": {"page"}, "ui_locales": {"es-ES en"}, "claims_locales": {"es"}, "acr_values": {"1"}, "response_mode": {"query"},
	}
	code := s.authorize(t, c, authorizePath(clientID, optional))
	s.exchangeCode(t, code)
}

func TestAuthorizationRequestWithoutStateOrNonce(t *testing.T) {
	s := newTestServer(t, false)
	c := browser(t)
	s.authorize(t, c, authorizePath(clientID, nil)) // login

	path := authorizePath(clientID, nil)
	u, _ := url.Parse(path)
	params := u.Query()
	params.Del("state")
	params.Del("nonce")
	resp, _ := get(t, c, s.url("/authorize?"+params.Encode()))
	callback := callbackParams(t, resp)
	if callback.Get("code") == "" || callback.Has("state") {
		t.Fatalf("Expected a code without state: %v", callback)
	}
}

func TestAuthorizationWithPOST(t *testing.T) {
	s := newTestServer(t, false)
	c := browser(t)
	s.authorize(t, c, authorizePath(clientID, nil)) // login

	u, _ := url.Parse(authorizePath(clientID, nil))
	resp, _ := postForm(t, c, s.url("/authorize"), u.Query())
	if callbackParams(t, resp).Get("code") == "" {
		t.Fatal("Expected a code with a POST request")
	}
}

func TestLoginHint(t *testing.T) {
	s := newTestServer(t, false)
	c := browser(t)

	resp, _ := get(t, c, s.url(authorizePath(clientID, url.Values{"login_hint": {"user"}})))
	login := expectLoginRedirect(t, resp)
	if login.Query().Get("login_hint") != "user" {
		t.Fatalf("Expected the login hint in the login url: %s", login)
	}

	resp, body := get(t, c, s.URL+login.RequestURI())
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, `name="username" type="text" placeholder="Username" value="user"`) {
		t.Errorf("Expected the username to be prefilled: %s", body)
	}
}

func TestUserinfoWithTokenInTheBody(t *testing.T) {
	s := newTestServer(t, false)
	tk := s.exchangeCode(t, s.authorize(t, browser(t), authorizePath(clientID, nil)))

	resp, body := postForm(t, http.DefaultClient, s.url("/userinfo"), url.Values{"access_token": {tk.AccessToken}})
	expectStatus(t, resp, body, http.StatusOK)

	// only one method can be used
	resp, body = postForm(t, http.DefaultClient, s.url("/userinfo"), url.Values{"access_token": {tk.AccessToken}}, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+tk.AccessToken)
	})
	expectError(t, resp, body, http.StatusUnauthorized, "invalid_request")
}

func TestStandardClaims(t *testing.T) {
	s := newTestServer(t, false)
	tk := s.exchangeCode(t, s.authorize(t, browser(t), authorizePath(clientID, nil)))

	resp, body := s.userinfo(t, tk.AccessToken)
	expectStatus(t, resp, body, http.StatusOK)
	for _, expected := range []string{`"name":"Test User"`, `"given_name":"Test"`, `"family_name":"User"`, `"email_verified":false`} {
		if !strings.Contains(body, expected) {
			t.Errorf("Expected %s in userinfo: %s", expected, body)
		}
	}

	idToken := parseIDToken(t, tk.IDToken)
	if strings.Join(idToken.AuthMethods, " ") != "pwd" {
		t.Errorf("Expected amr pwd, got %v", idToken.AuthMethods)
	}
}

func TestCORS(t *testing.T) {
	s := newTestServer(t, false)

	req, _ := http.NewRequest(http.MethodOptions, s.url("/token"), nil)
	req.Header.Set("Origin", "https://spa.test")
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, body := do(t, http.DefaultClient, req)
	expectStatus(t, resp, body, http.StatusNoContent)
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" || !strings.Contains(resp.Header.Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Errorf("Expected CORS headers: %v", resp.Header)
	}

	req, _ = http.NewRequest(http.MethodGet, s.url("/.well-known/openid-configuration"), nil)
	req.Header.Set("Origin", "https://spa.test")
	resp, body = do(t, http.DefaultClient, req)
	expectStatus(t, resp, body, http.StatusOK)
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Error("Expected CORS in the discovery document")
	}

	// the endpoints that use the session cookie do not allow CORS
	req, _ = http.NewRequest(http.MethodGet, s.url("/login"), nil)
	req.Header.Set("Origin", "https://spa.test")
	resp, _ = do(t, http.DefaultClient, req)
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("Expected no CORS in the login page")
	}
}

func TestIssuerWithPath(t *testing.T) {
	s := newTestServer(t, false, func(b *api.Builder) {
		b.Issuer = "http://issuer.test/auth"
	})
	c := browser(t)

	resp, body := get(t, http.DefaultClient, s.url("/.well-known/openid-configuration"))
	expectStatus(t, resp, body, http.StatusOK)
	for _, expected := range []string{`"issuer":"http://issuer.test/auth"`, `"authorization_endpoint":"http://issuer.test/auth/authorize"`, `"jwks_uri":"http://issuer.test/auth/.well-known/jwks.json"`} {
		if !strings.Contains(body, expected) {
			t.Errorf("Expected %s in discovery: %s", expected, body)
		}
	}

	code := s.authorize(t, c, authorizePath(clientID, nil))
	tk := s.exchangeCode(t, code)
	resp, body = s.userinfo(t, tk.AccessToken)
	expectStatus(t, resp, body, http.StatusOK)

	resp, body = get(t, c, s.url("/login"))
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, `href="/auth/static/styles.css"`) {
		t.Errorf("Expected the static files under the issuer path: %s", body)
	}

	resp, _ = get(t, http.DefaultClient, s.URL+"/.well-known/openid-configuration")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected no discovery outside the issuer path, got %d", resp.StatusCode)
	}
}

func TestInvalidIssuer(t *testing.T) {
	for _, value := range []string{"issuer.test", "http://issuer.test/?a=b", "ftp://issuer.test", "http://issuer.test/#x"} {
		b := &api.Builder{Issuer: value, Audience: audience}
		if _, err := b.Build(); err == nil {
			t.Errorf("Expected %s to be an invalid issuer", value)
		}
	}
}

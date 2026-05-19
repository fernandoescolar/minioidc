package integration

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"testing"
)

// loginAndGetSession sets up a fresh session for the test user.
// The session cookie is stored in the shared testClient cookie jar.
func loginAndGetSession(t *testing.T) {
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
		return
	}
	if _, ok := postErr.(*url.Error); !ok {
		t.Fatalf("unexpected login error: %v", postErr)
	}
}

// extractInputValue finds the value attribute of an <input> by name in raw HTML.
func extractInputValue(body, name string) string {
	for _, pat := range []string{
		`<input[^>]+name="` + name + `"[^>]+value="([^"]*)"`,
		`<input[^>]+value="([^"]*)"[^>]+name="` + name + `"`,
	} {
		re := regexp.MustCompile(pat)
		if m := re.FindStringSubmatch(body); len(m) == 2 {
			return html.UnescapeString(m[1])
		}
	}
	return ""
}

// --- Profile hub ---

func Test_Profile_RequiresSession(t *testing.T) {
	testClient.Reset()
	req := testClient.NewRequest("GET", "/profile")
	resp, err := req.Send()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Close()

	// Without a session the client is redirected to login (follows → 200 login page).
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200 (login page), got %d", resp.StatusCode())
	}
}

func Test_Profile_ShowsPage(t *testing.T) {
	testClient.Reset()
	loginAndGetSession(t)

	req := testClient.NewRequest("GET", "/profile")
	resp, err := req.Send()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode(), resp.BodyAsString())
	}
}

// --- Change password ---

func Test_ChangePassword_ShowsForm(t *testing.T) {
	testClient.Reset()
	loginAndGetSession(t)

	resp, err := testClient.NewRequest("GET", "/profile/password").Send()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode())
	}
	if getCSRFValue(resp) == "" {
		t.Fatal("expected CSRF token in password form")
	}
}

func Test_ChangePassword_WrongCurrentPassword(t *testing.T) {
	testClient.Reset()
	loginAndGetSession(t)

	getResp, err := testClient.NewRequest("GET", "/profile/password").Send()
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	csrf := getCSRFValue(getResp)
	getResp.Close()

	req := testClient.NewRequest("POST", "/profile/password")
	req.AddForm("current_password", "wrongpassword")
	req.AddForm("new_password", "newpassword")
	req.AddForm("confirm_password", "newpassword")
	req.AddForm("__csrf", csrf)

	resp, err := req.Send()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200 with error page, got %d", resp.StatusCode())
	}
}

func Test_ChangePassword_MismatchedNewPasswords(t *testing.T) {
	testClient.Reset()
	loginAndGetSession(t)

	getResp, err := testClient.NewRequest("GET", "/profile/password").Send()
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	csrf := getCSRFValue(getResp)
	getResp.Close()

	req := testClient.NewRequest("POST", "/profile/password")
	req.AddForm("current_password", "password")
	req.AddForm("new_password", "newpass1")
	req.AddForm("confirm_password", "newpass2")
	req.AddForm("__csrf", csrf)

	resp, err := req.Send()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200 with error page, got %d", resp.StatusCode())
	}
}

func Test_ChangePassword_Success(t *testing.T) {
	testClient.Reset()
	loginAndGetSession(t)

	getResp, err := testClient.NewRequest("GET", "/profile/password").Send()
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	csrf := getCSRFValue(getResp)
	getResp.Close()

	req := testClient.NewRequest("POST", "/profile/password")
	req.AddForm("current_password", "password")
	req.AddForm("new_password", "password") // keep same so other tests still pass
	req.AddForm("confirm_password", "password")
	req.AddForm("__csrf", csrf)

	resp, err := req.Send()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode(), resp.BodyAsString())
	}
}

// --- MFA management ---

func Test_ProfileMFA_ShowsPage(t *testing.T) {
	testClient.Reset()
	loginAndGetSession(t)

	resp, err := testClient.NewRequest("GET", "/profile/mfa").Send()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode(), resp.BodyAsString())
	}
	if getCSRFValue(resp) == "" {
		t.Fatal("expected CSRF token in MFA page")
	}
}

func Test_ProfileMFA_InvalidCode(t *testing.T) {
	testClient.Reset()
	loginAndGetSession(t)

	getResp, err := testClient.NewRequest("GET", "/profile/mfa").Send()
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	body := getResp.BodyAsString()
	getResp.Close()

	csrf := extractInputValue(body, "__csrf")
	iv := extractInputValue(body, "verification_iv")

	if csrf == "" {
		t.Fatal("expected CSRF token in MFA page")
	}
	if iv == "" {
		t.Fatal("expected verification_iv in MFA page")
	}

	req := testClient.NewRequest("POST", "/profile/mfa")
	req.AddForm("action", "add")
	req.AddForm("verification_iv", iv)
	req.AddForm("verification_code", "000000")
	req.AddForm("__csrf", csrf)

	resp, err := req.Send()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Close()

	// Invalid code → re-render the page (200) showing the error
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected 200 with error, got %d", resp.StatusCode())
	}
}

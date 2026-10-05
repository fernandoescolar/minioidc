package api_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/api"
	"github.com/fxamacker/cbor/v2"
	"github.com/pquerna/otp/totp"
)

const passkeyOrigin = "http://issuer.test"

var b64 = base64.RawURLEncoding

// authenticator is a software passkey: it answers the WebAuthn ceremonies as
// a browser with a platform authenticator would do
type authenticator struct {
	t      *testing.T
	key    *ecdsa.PrivateKey
	id     []byte
	user   []byte
	count  uint32
	origin string
}

func newAuthenticator(t *testing.T) *authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &authenticator{t: t, key: key, id: id, origin: passkeyOrigin}
}

// the options of the server, with the binary values base64url encoded
type webauthnOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		UserVerification       string `json:"userVerification"`
		AuthenticatorSelection struct {
			ResidentKey      string `json:"residentKey"`
			UserVerification string `json:"userVerification"`
		} `json:"authenticatorSelection"`
	} `json:"publicKey"`
}

func (a *authenticator) clientData(ceremony, challenge string) []byte {
	data, _ := json.Marshal(map[string]interface{}{"type": ceremony, "challenge": challenge, "origin": a.origin, "crossOrigin": false})
	return data
}

// authData is the authenticator data: the flags are user present (UP) and user verified (UV)
func (a *authenticator) authData(rpID string, attested []byte) []byte {
	a.count++
	flags := byte(0x01 | 0x04)
	if attested != nil {
		flags |= 0x40
	}

	rpHash := sha256.Sum256([]byte(rpID))
	data := append([]byte{}, rpHash[:]...)
	data = append(data, flags)
	data = binary.BigEndian.AppendUint32(data, a.count)
	return append(data, attested...)
}

// create answers navigator.credentials.create()
func (a *authenticator) create(options webauthnOptions) map[string]interface{} {
	a.t.Helper()
	user, err := b64.DecodeString(options.PublicKey.User.ID)
	if err != nil {
		a.t.Fatal(err)
	}
	a.user = user

	coseKey, err := cbor.Marshal(map[int]interface{}{
		1: 2, 3: -7, -1: 1, // EC2, ES256, P-256
		-2: a.key.X.FillBytes(make([]byte, 32)),
		-3: a.key.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		a.t.Fatal(err)
	}

	attested := make([]byte, 16) // AAGUID
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(a.id)))
	attested = append(attested, a.id...)
	attested = append(attested, coseKey...)

	attestation, err := cbor.Marshal(map[string]interface{}{
		"fmt": "none", "attStmt": map[string]interface{}{}, "authData": a.authData(options.PublicKey.RP.ID, attested),
	})
	if err != nil {
		a.t.Fatal(err)
	}

	return map[string]interface{}{
		"id": b64.EncodeToString(a.id), "rawId": b64.EncodeToString(a.id), "type": "public-key",
		"response": map[string]interface{}{
			"clientDataJSON":    b64.EncodeToString(a.clientData("webauthn.create", options.PublicKey.Challenge)),
			"attestationObject": b64.EncodeToString(attestation),
			"transports":        []string{"internal"},
		},
		"clientExtensionResults": map[string]interface{}{},
	}
}

// get answers navigator.credentials.get()
func (a *authenticator) get(options webauthnOptions) map[string]interface{} {
	a.t.Helper()
	authData := a.authData(options.PublicKey.RPID, nil)
	clientData := a.clientData("webauthn.get", options.PublicKey.Challenge)
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		a.t.Fatal(err)
	}

	return map[string]interface{}{
		"id": b64.EncodeToString(a.id), "rawId": b64.EncodeToString(a.id), "type": "public-key",
		"response": map[string]interface{}{
			"clientDataJSON":    b64.EncodeToString(clientData),
			"authenticatorData": b64.EncodeToString(authData),
			"signature":         b64.EncodeToString(signature),
			"userHandle":        b64.EncodeToString(a.user),
		},
		"clientExtensionResults": map[string]interface{}{},
	}
}

// postPasskey posts JSON to a passkey endpoint, as passkey.js does
func postPasskey(t *testing.T, c *http.Client, u string, body interface{}) (*http.Response, string) {
	t.Helper()
	var data []byte
	if body != nil {
		data, _ = json.Marshal(body)
	}

	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Minioidc-Passkey", "1")
	return do(t, c, req)
}

func parseOptions(t *testing.T, body string) webauthnOptions {
	t.Helper()
	var options webauthnOptions
	if err := json.Unmarshal([]byte(body), &options); err != nil || options.PublicKey.Challenge == "" {
		t.Fatalf("Invalid WebAuthn options %s: %v", body, err)
	}

	return options
}

// registerPasskey adds a passkey to the signed in user of the browser
func (s *testServer) registerPasskey(t *testing.T, c *http.Client, a *authenticator, name string) {
	t.Helper()
	resp, body := postPasskey(t, c, s.url("/profile/passkeys/register/begin"), nil)
	expectStatus(t, resp, body, http.StatusOK)
	options := parseOptions(t, body)
	if options.PublicKey.AuthenticatorSelection.ResidentKey != "required" || options.PublicKey.AuthenticatorSelection.UserVerification != "required" {
		t.Errorf("Expected a discoverable credential with user verification: %s", body)
	}

	resp, body = postPasskey(t, c, s.url("/profile/passkeys/register/finish?name="+url.QueryEscape(name)), a.create(options))
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, `"redirect":"/profile/passkeys?added=1"`) {
		t.Errorf("Unexpected registration answer: %s", body)
	}
}

// passkeyLogin signs in with the passkey and returns the answer of the server
func (s *testServer) passkeyLogin(t *testing.T, c *http.Client, a *authenticator, query string) (*http.Response, string) {
	t.Helper()
	resp, body := postPasskey(t, c, s.url("/passkey/login/begin"), nil)
	expectStatus(t, resp, body, http.StatusOK)
	options := parseOptions(t, body)
	if options.PublicKey.UserVerification != "required" {
		t.Errorf("Expected the user verification: %s", body)
	}

	return postPasskey(t, c, s.url("/passkey/login/finish"+query), a.get(options))
}

func TestPasskeyRegistrationAndLogin(t *testing.T) {
	s := newTestServer(t, false)
	c := s.loginAs(t, username).http
	a := newAuthenticator(t)
	s.registerPasskey(t, c, a, "  My   Laptop ")

	resp, body := get(t, c, s.url("/profile/passkeys"))
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, "My Laptop") || !strings.Contains(body, "Not used yet") {
		t.Errorf("Expected the new passkey: %s", body)
	}
	resp, body = get(t, c, s.url("/profile"))
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, "/profile/passkeys") {
		t.Errorf("Expected the passkeys in the profile: %s", body)
	}

	// the login page offers the passkeys
	browser2 := browser(t)
	resp, body = get(t, browser2, s.url("/login"))
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, "data-passkey-login") || !strings.Contains(body, `autocomplete="username webauthn"`) {
		t.Errorf("Expected the passkey login: %s", body)
	}

	// a login with the passkey, without a password, continues to the return_url
	returnURL := authorizePath(clientID, nil)
	resp, body = s.passkeyLogin(t, browser2, a, "?return_url="+url.QueryEscape(returnURL))
	expectStatus(t, resp, body, http.StatusOK)
	var result struct {
		Redirect string `json:"redirect"`
	}
	if err := json.Unmarshal([]byte(body), &result); err != nil || result.Redirect != returnURL {
		t.Fatalf("Expected the return_url, got %s", body)
	}

	code := s.authorize(t, browser2, result.Redirect)
	claims := parseIDToken(t, s.exchangeCode(t, code).IDToken)
	if claims.Subject != "1" || !slices.Contains(claims.AuthMethods, "hwk") || !slices.Contains(claims.AuthMethods, "mfa") {
		t.Errorf("Expected a passkey login of the user, got %+v", claims)
	}

	resp, body = get(t, c, s.url("/profile/passkeys"))
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, "Last used") {
		t.Errorf("Expected the last use of the passkey: %s", body)
	}
}

// enrollMFA adds an authenticator app to the signed in user of the browser
func (s *testServer) enrollMFA(t *testing.T, c *http.Client) {
	t.Helper()
	resp, body := get(t, c, s.url("/mfa/create"))
	expectStatus(t, resp, body, http.StatusOK)
	secret := mfaIVRegex.FindStringSubmatch(body)[1]
	code, _ := totp.GenerateCode(secret, s.clock.Now())
	resp, body = postForm(t, c, s.url("/mfa/create"), url.Values{
		"verification_iv": {secret}, "verification_code": {code}, "__csrf": {csrfRegex.FindStringSubmatch(body)[1]},
	})
	expectStatus(t, resp, body, http.StatusFound)
}

func TestPasskeyLoginIsTheMFA(t *testing.T) {
	s := newTestServer(t, true)
	c := s.loginAs(t, "other").http
	// the MFA is required before adding a passkey
	resp, _ := postPasskey(t, c, s.url("/profile/passkeys/register/begin"), nil)
	expectRedirectTo(t, resp, "/mfa/create")

	s.enrollMFA(t, c)
	a := newAuthenticator(t)
	s.registerPasskey(t, c, a, "")

	// the passkey verifies the user: the MFA is not asked
	passkeyBrowser := browser(t)
	resp, body := s.passkeyLogin(t, passkeyBrowser, a, "")
	expectStatus(t, resp, body, http.StatusOK)
	resp, body = get(t, passkeyBrowser, s.url("/profile"))
	expectStatus(t, resp, body, http.StatusOK)

	resp, body = get(t, passkeyBrowser, s.url("/profile/passkeys"))
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, "Passkey 1") {
		t.Errorf("Expected the default name of the passkey: %s", body)
	}
}

func TestPasskeyLoginRejections(t *testing.T) {
	s := newTestServer(t, false)
	c := s.loginAs(t, username).http
	a := newAuthenticator(t)
	s.registerPasskey(t, c, a, "laptop")

	// the requests of the scripts need the header (CSRF)
	resp, body := postForm(t, browser(t), s.url("/passkey/login/begin"), url.Values{})
	expectStatus(t, resp, body, http.StatusForbidden)

	// each challenge is used once
	resp, body = postPasskey(t, browser(t), s.url("/passkey/login/begin"), nil)
	expectStatus(t, resp, body, http.StatusOK)
	answer := a.get(parseOptions(t, body))
	resp, body = postPasskey(t, browser(t), s.url("/passkey/login/finish"), answer)
	expectStatus(t, resp, body, http.StatusOK)
	resp, body = postPasskey(t, browser(t), s.url("/passkey/login/finish"), answer)
	expectStatus(t, resp, body, http.StatusBadRequest)

	// the challenges expire
	resp, body = postPasskey(t, browser(t), s.url("/passkey/login/begin"), nil)
	expectStatus(t, resp, body, http.StatusOK)
	options := parseOptions(t, body)
	s.clock.Advance(6 * time.Minute)
	resp, body = postPasskey(t, browser(t), s.url("/passkey/login/finish"), a.get(options))
	expectStatus(t, resp, body, http.StatusBadRequest)

	// the passkeys only work in the site of the issuer
	phishing := *a
	phishing.origin = "https://issuer-login.example"
	resp, body = s.passkeyLogin(t, browser(t), &phishing, "")
	expectStatus(t, resp, body, http.StatusBadRequest)

	// an unknown passkey
	resp, body = s.passkeyLogin(t, browser(t), newAuthenticator(t), "")
	expectStatus(t, resp, body, http.StatusBadRequest)

	// a copy of the passkey: its sign count goes back
	a.count = 0
	resp, body = s.passkeyLogin(t, browser(t), a, "")
	expectStatus(t, resp, body, http.StatusBadRequest)
	if !strings.Contains(body, "cloned") {
		t.Errorf("Expected a cloned passkey error: %s", body)
	}

	// an external return_url is ignored
	b := newAuthenticator(t)
	s.registerPasskey(t, c, b, "phone")
	resp, body = s.passkeyLogin(t, browser(t), b, "?return_url="+url.QueryEscape("https://evil.test/"))
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, `"redirect":"/"`) {
		t.Errorf("Expected the home as redirect: %s", body)
	}
}

var passkeyIDRegex = regexp.MustCompile(`name="id" value="([^"]+)"`)

func TestPasskeyManagementRequiresARecentLogin(t *testing.T) {
	s := newTestServer(t, false)
	c := s.loginAs(t, username).http
	a := newAuthenticator(t)
	s.registerPasskey(t, c, a, "laptop")

	resp, body := get(t, c, s.url("/profile/passkeys"))
	expectStatus(t, resp, body, http.StatusOK)
	id := passkeyIDRegex.FindStringSubmatch(body)[1]

	// the name can be changed at any time
	s.clock.Advance(11 * time.Minute)
	resp, body = get(t, c, s.url("/profile/passkeys"))
	expectStatus(t, resp, body, http.StatusOK)
	csrf := csrfRegex.FindStringSubmatch(body)[1]
	resp, body = postForm(t, c, s.url("/profile/passkeys"), url.Values{"action": {"rename"}, "id": {id}, "name": {"work laptop"}, "__csrf": {csrf}})
	expectRedirectTo(t, resp, "/profile/passkeys?renamed=1")

	// but a stolen session cannot add or remove passkeys
	resp, body = get(t, c, s.url("/profile/passkeys"))
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, "work laptop") || !strings.Contains(body, "sign in again") || strings.Contains(body, "data-passkey-register") {
		t.Errorf("Expected a reauthentication: %s", body)
	}
	csrf = csrfRegex.FindStringSubmatch(body)[1]
	resp, body = postPasskey(t, c, s.url("/profile/passkeys/register/begin"), nil)
	expectStatus(t, resp, body, http.StatusForbidden)
	resp, body = postForm(t, c, s.url("/profile/passkeys"), url.Values{"action": {"delete"}, "id": {id}, "__csrf": {csrf}})
	expectStatus(t, resp, body, http.StatusForbidden)

	// after a new login, the passkey can be removed
	c2 := s.loginAs(t, username).http
	resp, body = get(t, c2, s.url("/profile/passkeys"))
	expectStatus(t, resp, body, http.StatusOK)
	resp, body = postForm(t, c2, s.url("/profile/passkeys"), url.Values{"action": {"delete"}, "id": {id}, "__csrf": {csrfRegex.FindStringSubmatch(body)[1]}})
	expectRedirectTo(t, resp, "/profile/passkeys?deleted=1")

	resp, body = s.passkeyLogin(t, browser(t), a, "")
	expectStatus(t, resp, body, http.StatusBadRequest)
}

func TestPasskeysOfOtherUsers(t *testing.T) {
	s := newTestServer(t, false)
	a := newAuthenticator(t)
	owner := s.loginAs(t, username).http
	s.registerPasskey(t, owner, a, "laptop")
	resp, body := get(t, owner, s.url("/profile/passkeys"))
	expectStatus(t, resp, body, http.StatusOK)
	id := passkeyIDRegex.FindStringSubmatch(body)[1]

	other := s.loginAs(t, "other").http
	resp, body = get(t, other, s.url("/profile/passkeys"))
	expectStatus(t, resp, body, http.StatusOK)
	if strings.Contains(body, "laptop") {
		t.Errorf("Expected only the passkeys of the user: %s", body)
	}

	// the page has no forms without passkeys: the token of another page
	resp, body = get(t, other, s.url("/profile/password"))
	expectStatus(t, resp, body, http.StatusOK)
	csrf := csrfRegex.FindStringSubmatch(body)[1]
	resp, body = postForm(t, other, s.url("/profile/passkeys"), url.Values{"action": {"delete"}, "id": {id}, "__csrf": {csrf}})
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, "does not exist") {
		t.Errorf("Expected a not found error: %s", body)
	}
	resp, body = get(t, other, s.url("/profile/password"))
	csrf = csrfRegex.FindStringSubmatch(body)[1]
	resp, body = postForm(t, other, s.url("/profile/passkeys"), url.Values{"action": {"rename"}, "id": {id}, "name": {"mine"}, "__csrf": {csrf}})
	expectStatus(t, resp, body, http.StatusOK)
	if !strings.Contains(body, "does not exist") {
		t.Errorf("Expected a not found error: %s", body)
	}

	resp, body = s.passkeyLogin(t, browser(t), a, "")
	expectStatus(t, resp, body, http.StatusOK)
}

func TestPasskeysInTheAdmin(t *testing.T) {
	s, database := newAdminServer(t)
	admin := s.loginAs(t, username)
	a := newAuthenticator(t)
	s.registerPasskey(t, admin.http, a, "laptop")

	var users []struct {
		Subject  string `json:"subject"`
		Passkeys int    `json:"passkeys"`
	}
	admin.listUsers(&users)
	if users[1].Subject != "1" || users[1].Passkeys != 1 {
		t.Errorf("Expected the passkey of the user: %+v", users)
	}

	var passkeys []struct {
		ID         string     `json:"id"`
		Name       string     `json:"name"`
		LastUsedAt *time.Time `json:"last_used_at"`
	}
	admin.call(http.MethodGet, "/users/1/passkeys", nil, http.StatusOK, &passkeys)
	if len(passkeys) != 1 || passkeys[0].Name != "laptop" || passkeys[0].LastUsedAt != nil {
		t.Fatalf("Unexpected passkeys: %+v", passkeys)
	}

	// the passkeys are in SQLite: they survive a restart
	restarted := newTestServer(t, false, withAdmin(database))
	resp, body := restarted.passkeyLogin(t, browser(t), a, "")
	expectStatus(t, resp, body, http.StatusOK)

	admin.call(http.MethodDelete, "/users/1/passkeys/"+url.PathEscape(passkeys[0].ID), nil, http.StatusNoContent, nil)
	admin.call(http.MethodDelete, "/users/1/passkeys/"+url.PathEscape(passkeys[0].ID), nil, http.StatusNotFound, nil)
	resp, body = s.passkeyLogin(t, browser(t), a, "")
	expectStatus(t, resp, body, http.StatusBadRequest)
}

func TestPasskeysCanBeDisabled(t *testing.T) {
	s := newTestServer(t, false, func(b *api.Builder) { b.DisablePasskeys = true })

	resp, body := get(t, browser(t), s.url("/login"))
	expectStatus(t, resp, body, http.StatusOK)
	if strings.Contains(body, "passkey") {
		t.Errorf("Expected no passkeys in the login: %s", body)
	}

	resp, _ = postPasskey(t, browser(t), s.url("/passkey/login/begin"), nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected no passkey endpoints, got %d", resp.StatusCode)
	}

	c := s.loginAs(t, username).http
	resp, body = get(t, c, s.url("/profile"))
	expectStatus(t, resp, body, http.StatusOK)
	if strings.Contains(body, "/profile/passkeys") {
		t.Errorf("Expected no passkeys in the profile: %s", body)
	}
}

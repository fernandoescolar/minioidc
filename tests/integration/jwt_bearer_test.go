package integration

import (
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const jwtBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// signAssertion signs a jwt-bearer grant assertion of myclient about a user
// (RFC 7523 section 3) with the test client key
func signAssertion(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	now := time.Now()
	base := jwt.MapClaims{
		"iss": "myclient",
		"sub": "0000001",
		"aud": fakeIssuer + "/connect/token",
		"jti": uuid.NewString(),
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	}
	for key, value := range claims {
		if value == nil {
			delete(base, key)
			continue
		}
		base[key] = value
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, base).SignedString(testClientKey)
	if err != nil {
		t.Fatal(err)
	}

	return signed
}

func jwtBearerRequest(clientID, secret, assertion, scope string) *ClientRequest {
	req := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	if clientID != "" {
		req.SetBasicAuth(clientID, secret)
	}
	req.AddForm("grant_type", jwtBearerGrant)
	if assertion != "" {
		req.AddForm("assertion", assertion)
	}
	if scope != "" {
		req.AddForm("scope", scope)
	}

	return req
}

func sendExpectingStatus(t *testing.T, req *ClientRequest, status int) *TokenResponse {
	t.Helper()
	resp, err := req.Send()
	if err != nil {
		t.Fatalf("jwt-bearer grant error: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode() != status {
		t.Fatalf("expected %d, got %d: %s", status, resp.StatusCode(), resp.BodyAsString())
	}

	tokens := &TokenResponse{}
	if status == http.StatusOK {
		if err := resp.BodyAsJSON(tokens); err != nil {
			t.Fatalf("parse jwt-bearer response: %v", err)
		}
	}

	return tokens
}

func Test_JWTBearer_ValidAssertion(t *testing.T) {
	testClient.Reset()
	tokens := sendExpectingStatus(t, jwtBearerRequest("myclient", "secret", signAssertion(t, nil), "email offline_access"), http.StatusOK)

	if tokens.AccessToken == "" {
		t.Fatal("expected access_token in jwt-bearer response")
	}
	if tokens.RefreshToken == nil || *tokens.RefreshToken == "" {
		t.Fatal("expected refresh_token with offline_access")
	}
}

// The user has not authenticated: the grant does not issue ID tokens
func Test_JWTBearer_WithOpenIDScope(t *testing.T) {
	testClient.Reset()
	tokens := sendExpectingStatus(t, jwtBearerRequest("myclient", "secret", signAssertion(t, nil), "openid"), http.StatusOK)

	if tokens.IDToken != nil {
		t.Fatal("expected no id_token: the user has not authenticated")
	}
}

// Regression: the tokens issued by the server are not valid assertions (any
// leaked token would give tokens of any client)
func Test_JWTBearer_RejectsTheTokensOfTheServer(t *testing.T) {
	accessToken := getAccessTokenViaPassword(t, "")
	testClient.Reset()
	sendExpectingStatus(t, jwtBearerRequest("myclient", "secret", accessToken, ""), http.StatusBadRequest)
	sendExpectingStatus(t, jwtBearerRequest("myclient", "secret", getIDToken(t, ""), ""), http.StatusBadRequest)
}

func Test_JWTBearer_AssertionCanOnlyBeUsedOnce(t *testing.T) {
	testClient.Reset()
	assertion := signAssertion(t, nil)
	sendExpectingStatus(t, jwtBearerRequest("myclient", "secret", assertion, ""), http.StatusOK)
	sendExpectingStatus(t, jwtBearerRequest("myclient", "secret", assertion, ""), http.StatusBadRequest)
}

func Test_JWTBearer_InvalidAssertions(t *testing.T) {
	testClient.Reset()
	for name, assertion := range map[string]string{
		"not a jwt":      "not-a-valid-jwt",
		"wrong audience": signAssertion(t, jwt.MapClaims{"aud": "https://other.example.com/token"}),
		"expired":        signAssertion(t, jwt.MapClaims{"exp": time.Now().Add(-time.Hour).Unix()}),
		"without jti":    signAssertion(t, jwt.MapClaims{"jti": nil}),
		"other issuer":   signAssertion(t, jwt.MapClaims{"iss": "publicclient"}),
		"unknown user":   signAssertion(t, jwt.MapClaims{"sub": "nobody"}),
	} {
		t.Run(name, func(t *testing.T) {
			sendExpectingStatus(t, jwtBearerRequest("myclient", "secret", assertion, ""), http.StatusBadRequest)
		})
	}
}

func Test_JWTBearer_MissingAssertion(t *testing.T) {
	testClient.Reset()
	sendExpectingStatus(t, jwtBearerRequest("myclient", "secret", "", ""), http.StatusBadRequest)
}

func Test_JWTBearer_RequiresClientAuthentication(t *testing.T) {
	testClient.Reset()
	assertion := signAssertion(t, nil)
	sendExpectingStatus(t, jwtBearerRequest("", "", assertion, ""), http.StatusUnauthorized)
	sendExpectingStatus(t, jwtBearerRequest("myclient", "wrong", assertion, ""), http.StatusUnauthorized)
	sendExpectingStatus(t, jwtBearerRequest("nonexistentclient", "secret", assertion, ""), http.StatusUnauthorized)
}

// getAccessTokenViaPassword returns an access token of the test user
func getAccessTokenViaPassword(t *testing.T, scope string) string {
	t.Helper()
	req := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	req.SetBasicAuth("myclient", "secret")
	req.AddForm("grant_type", "password")
	req.AddForm("username", "user")
	req.AddForm("password", "password")
	if scope != "" {
		req.AddForm("scope", scope)
	}

	tokens := sendExpectingStatus(t, req, http.StatusOK)
	if tokens.AccessToken == "" {
		t.Fatal("expected access_token from the password grant")
	}

	return tokens.AccessToken
}

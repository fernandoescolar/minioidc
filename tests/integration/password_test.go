package integration

import (
	"fmt"
	"net/http"
	"testing"
)

type passwordTestCase struct {
	name               string
	clientID           string
	secret             string
	username           string
	password           string
	scope              string
	expectedStatus     int
	expectAccessToken  bool
	expectdIDToken     bool
	expectRefreshToken bool
}

func Test_Password_Basic(t *testing.T) {
	testCases := []passwordTestCase{
		{
			name:               "valid client and user",
			clientID:           "myclient",
			secret:             "secret",
			username:           "user",
			password:           "password",
			scope:              "",
			expectedStatus:     http.StatusOK,
			expectAccessToken:  true,
			expectdIDToken:     false,
			expectRefreshToken: false,
		},
		{
			name:               "valid client and user with id_token",
			clientID:           "myclient",
			secret:             "secret",
			username:           "user",
			password:           "password",
			scope:              "openid",
			expectedStatus:     http.StatusOK,
			expectAccessToken:  true,
			expectdIDToken:     true,
			expectRefreshToken: false,
		},
		{
			name:               "invalid client",
			clientID:           "invalid",
			secret:             "secret",
			username:           "user",
			password:           "password",
			scope:              "",
			expectedStatus:     http.StatusUnauthorized,
			expectAccessToken:  false,
			expectdIDToken:     false,
			expectRefreshToken: false,
		},
		{
			name:               "invalid user",
			clientID:           "myclient",
			secret:             "secret",
			username:           "invalid",
			password:           "password",
			scope:              "",
			expectedStatus:     http.StatusUnauthorized,
			expectAccessToken:  false,
			expectdIDToken:     false,
			expectRefreshToken: false,
		},
		{
			name:               "invalid password",
			clientID:           "myclient",
			secret:             "secret",
			username:           "user",
			password:           "invalid",
			scope:              "",
			expectedStatus:     http.StatusUnauthorized,
			expectAccessToken:  false,
			expectdIDToken:     false,
			expectRefreshToken: false,
		},
		{
			name:               "invalid scope",
			clientID:           "myclient",
			secret:             "secret",
			username:           "user",
			password:           "password",
			scope:              "invalid",
			expectedStatus:     http.StatusBadRequest,
			expectAccessToken:  false,
			expectdIDToken:     false,
			expectRefreshToken: false,
		},
	}

	for _, tc := range testCases {
		name := fmt.Sprintf("Password_client_basic_%s", tc.name)
		t.Run(name, func(t *testing.T) {
			req := createPassworBasicRequest(tc)
			runAndValidatePasswordTest(t, req, tc)
		})

		name = fmt.Sprintf("ClientCredentials_client_post_%s", tc.name)
		t.Run(name, func(t *testing.T) {
			req := createPasswordPostRequest(tc)
			runAndValidatePasswordTest(t, req, tc)
		})
	}
}

func createPassworBasicRequest(testCase passwordTestCase) *ClientRequest {
	req := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	req.SetBasicAuth(testCase.clientID, testCase.secret)
	req.AddForm("grant_type", "password")
	req.AddForm("username", testCase.username)
	req.AddForm("password", testCase.password)
	if testCase.scope != "" {
		req.AddForm("scope", testCase.scope)
	}

	return req
}

func createPasswordPostRequest(testCase passwordTestCase) *ClientRequest {
	req := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	req.AddForm("client_id", testCase.clientID)
	req.AddForm("client_secret", testCase.secret)
	req.AddForm("grant_type", "password")
	req.AddForm("username", testCase.username)
	req.AddForm("password", testCase.password)
	if testCase.scope != "" {
		req.AddForm("scope", testCase.scope)
	}

	return req
}

func runAndValidatePasswordTest(t *testing.T, request *ClientRequest, testCase passwordTestCase) {
	resp, err := request.Send()
	if err != nil {
		t.Fatal(err)
	}

	defer resp.Close()
	if resp.StatusCode() != testCase.expectedStatus {
		t.Fatalf("expected status %d, got %d", testCase.expectedStatus, resp.StatusCode())
	}

	if testCase.expectedStatus >= http.StatusBadRequest {
		return
	}

	tokens := &TokenResponse{}
	err = resp.BodyAsJSON(tokens)
	if err != nil {
		t.Fatal(err)
	}

	if tokens.AccessToken == "" && testCase.expectAccessToken {
		t.Fatalf("expected access token, got empty")
	}
	if tokens.AccessToken != "" && !testCase.expectAccessToken {
		t.Fatalf("not expected access token, got not empty")
	}

	if tokens.IDToken == nil && testCase.expectdIDToken {
		t.Fatalf("expected access token, got empty")
	}

	if tokens.IDToken != nil && !testCase.expectdIDToken {
		t.Fatalf("not expected access token, got not empty")
	}

	if tokens.RefreshToken == nil && testCase.expectRefreshToken {
		t.Fatalf("expected access token, got empty")
	}

	if tokens.RefreshToken != nil && !testCase.expectRefreshToken {
		t.Fatalf("not expected access token, got not empty")
	}

	if tokens.TokenType != "bearer" {
		t.Fatalf("expected token type %q, got %q", "bearer", tokens.TokenType)
	}

	if tokens.ExpiresIn == 0 {
		t.Fatalf("expected expires in > 0, got %d", tokens.ExpiresIn)
	}
}

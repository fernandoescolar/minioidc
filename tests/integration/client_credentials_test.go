package integration

import (
	"fmt"
	"net/http"
	"testing"
)

type clientCredentialsTestCase struct {
	name               string
	clientID           string
	secret             string
	scope              string
	expectedStatus     int
	expectAccessToken  bool
	expectdIDToken     bool
	expectRefreshToken bool
}

func Test_ClientCredentials_Basic(t *testing.T) {
	testCases := []clientCredentialsTestCase{
		{
			name:               "valid client",
			clientID:           "myclient",
			secret:             "secret",
			scope:              "",
			expectedStatus:     http.StatusOK,
			expectAccessToken:  true,
			expectdIDToken:     false,
			expectRefreshToken: false,
		},
		{
			name:               "valid client with id_token",
			clientID:           "myclient",
			secret:             "secret",
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
			scope:              "",
			expectedStatus:     http.StatusUnauthorized,
			expectAccessToken:  false,
			expectdIDToken:     false,
			expectRefreshToken: false,
		},
		{
			name:               "invalid secret",
			clientID:           "myclient",
			secret:             "invalid",
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
			scope:              "invalid",
			expectedStatus:     http.StatusBadRequest,
			expectAccessToken:  false,
			expectdIDToken:     false,
			expectRefreshToken: false,
		},
	}

	for _, tc := range testCases {
		name := fmt.Sprintf("ClientCredentials_basic_%s", tc.name)
		t.Run(name, func(t *testing.T) {
			req := createClientCredentialsBasicRequest(tc)
			runAndValidateClientCredentialsTest(t, req, tc)
		})

		name = fmt.Sprintf("ClientCredentials_post_%s", tc.name)
		t.Run(name, func(t *testing.T) {
			req := createClientCredentialsPostRequest(tc)
			runAndValidateClientCredentialsTest(t, req, tc)
		})
	}
}

func createClientCredentialsBasicRequest(testCase clientCredentialsTestCase) *ClientRequest {
	req := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	req.SetBasicAuth(testCase.clientID, testCase.secret)
	req.AddForm("grant_type", "client_credentials")
	if testCase.scope != "" {
		req.AddForm("scope", testCase.scope)
	}

	return req
}

func createClientCredentialsPostRequest(testCase clientCredentialsTestCase) *ClientRequest {
	req := testClient.NewRequest("POST", testClient.Discovery.TokenEndpoint)
	req.AddForm("client_id", testCase.clientID)
	req.AddForm("client_secret", testCase.secret)
	req.AddForm("grant_type", "client_credentials")
	if testCase.scope != "" {
		req.AddForm("scope", testCase.scope)
	}

	return req
}

func runAndValidateClientCredentialsTest(t *testing.T, request *ClientRequest, testCase clientCredentialsTestCase) {
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

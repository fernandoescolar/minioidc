package integration

import (
	"encoding/json"
	"net/http"
	"testing"
)

// Test_Discovery verifies that the OpenID Connect discovery document is served
// with all required OIDC Core fields.
func Test_Discovery(t *testing.T) {
	req := testClient.NewRequest("GET", "/.well-known/openid-configuration")
	resp, err := req.Send()
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Close()

	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode())
	}

	doc := &DiscoveryResponse{}
	if err := resp.BodyAsJSON(doc); err != nil {
		t.Fatalf("cannot parse discovery response: %v", err)
	}

	if doc.Issuer == "" {
		t.Error("discovery: issuer is empty")
	}
	if doc.AuthorizationEndpoint == "" {
		t.Error("discovery: authorization_endpoint is empty")
	}
	if doc.TokenEndpoint == "" {
		t.Error("discovery: token_endpoint is empty")
	}
	if doc.JwksURI == "" {
		t.Error("discovery: jwks_uri is empty")
	}
	if doc.UserinfoEndpoint == "" {
		t.Error("discovery: userinfo_endpoint is empty")
	}
	if doc.IntrospectionEndpoint == "" {
		t.Error("discovery: introspection_endpoint is empty")
	}
	if len(doc.ResponseTypesSupported) == 0 {
		t.Error("discovery: response_types_supported is empty")
	}
	if len(doc.GrantTypesSupported) == 0 {
		t.Error("discovery: grant_types_supported is empty")
	}
	if len(doc.ScopesSupported) == 0 {
		t.Error("discovery: scopes_supported is empty")
	}
}

// Test_JWKS verifies that the JWKS endpoint returns at least one RSA public key
// with all mandatory fields.
func Test_JWKS(t *testing.T) {
	req := testClient.NewRequest("GET", testClient.Discovery.JwksURI)
	resp, err := req.Send()
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Close()

	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode())
	}

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	body := resp.BodyAsString()
	if err := json.Unmarshal([]byte(body), &jwks); err != nil {
		t.Fatalf("cannot parse JWKS response: %v", err)
	}

	if len(jwks.Keys) == 0 {
		t.Fatal("JWKS: no keys returned")
	}

	for i, key := range jwks.Keys {
		for _, field := range []string{"kty", "use", "kid", "n", "e"} {
			if v, ok := key[field]; !ok || v == "" {
				t.Errorf("JWKS key[%d]: missing or empty field %q", i, field)
			}
		}
		if key["kty"] != "RSA" {
			t.Errorf("JWKS key[%d]: expected kty=RSA, got %v", i, key["kty"])
		}
	}
}

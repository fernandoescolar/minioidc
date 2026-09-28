package cryptography

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"testing"
)

func TestParseJWKS(t *testing.T) {
	jwks := `{"keys":[
		{"kty":"RSA","use":"sig","kid":"rsa","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"},
		{"kty":"EC","crv":"P-256","kid":"ec","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"},
		{"kty":"OKP","crv":"Ed25519","kid":"ed","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
		{"kty":"RSA","use":"enc","kid":"encryption","n":"AQAB","e":"AQAB"},
		{"kty":"oct","kid":"symmetric","k":"c2VjcmV0"}
	]}`

	keys, err := ParseJWKS([]byte(jwks))
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 3 {
		t.Fatalf("Expected 3 signature keys, got %d", len(keys))
	}

	if _, ok := keys[0].Key.(*rsa.PublicKey); !ok || keys[0].KeyID != "rsa" {
		t.Error("Expected an RSA key")
	}
	if _, ok := keys[1].Key.(*ecdsa.PublicKey); !ok {
		t.Error("Expected an EC key")
	}
	if _, ok := keys[2].Key.(ed25519.PublicKey); !ok {
		t.Error("Expected an Ed25519 key")
	}
}

func TestParseJWKSRejectsInvalidKeys(t *testing.T) {
	for name, jwks := range map[string]string{
		"private key":        `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}]}`,
		"point not on curve": `{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"AAAAzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`,
		"unknown curve":      `{"keys":[{"kty":"EC","crv":"P-192","x":"AA","y":"AA"}]}`,
		"not JSON":           `keys`,
	} {
		if _, err := ParseJWKS([]byte(jwks)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}

	if _, err := ParseJWKS([]byte(`{"keys":[]}`)); err != nil {
		t.Errorf("Expected an empty JWKS to be valid: %v", err)
	}
}

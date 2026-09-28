package cryptography

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const testKey = "12345678901234567890123456789012"

func TestEncryptAndDecrypt(t *testing.T) {
	text := "Hello, World!"
	encrypted, err := Encrypts(testKey, text)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := Decrypts(testKey, encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if decrypted != text {
		t.Errorf("Expected %s, got %s", text, decrypted)
	}
}

func TestDecryptsDetectsTampering(t *testing.T) {
	encrypted, err := Encrypts(testKey, "session-id")
	if err != nil {
		t.Fatal(err)
	}

	last := encrypted[len(encrypted)-1]
	replacement := "A"
	if last == 'A' {
		replacement = "B"
	}

	if _, err := Decrypts(testKey, encrypted[:len(encrypted)-1]+replacement); err == nil {
		t.Error("Expected tampered ciphertext to fail")
	}

	if _, err := Decrypts("another key another key another k", encrypted); err == nil {
		t.Error("Expected decryption with another key to fail")
	}
}

func TestSHA256(t *testing.T) {
	// sha256("abc")
	expected := "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
	if got := SHA256("abc"); got != expected {
		t.Errorf("Expected %s, got %s", expected, got)
	}

	if strings.Contains(SHA256("secret-token"), "secret") {
		t.Error("Hash must not contain the plain text")
	}
}

func TestVerifyCodeChallenge(t *testing.T) {
	// RFC 7636 appendix B
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	if !VerifyCodeChallenge(CodeChallengeMethodS256, challenge, verifier) {
		t.Error("Expected valid code verifier")
	}

	if VerifyCodeChallenge(CodeChallengeMethodS256, challenge, verifier[1:]+"x") {
		t.Error("Expected invalid code verifier")
	}

	if VerifyCodeChallenge("plain", verifier, verifier) {
		t.Error("plain method must not be supported")
	}

	if VerifyCodeChallenge(CodeChallengeMethodS256, challenge, "short") {
		t.Error("Expected too short code verifier to be rejected")
	}
}

func TestVerifyTOTP(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	code, err := totp.GenerateCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}

	if !VerifyTOTP(TOTPMethod, secret, code, now) {
		t.Error("Expected valid TOTP code")
	}

	if !VerifyTOTP(TOTPMethod, secret, code, now.Add(30*time.Second)) {
		t.Error("Expected TOTP code to be valid with one period of skew")
	}

	if VerifyTOTP(TOTPMethod, secret, code, now.Add(5*time.Minute)) {
		t.Error("Expected old TOTP code to be invalid")
	}

	legacyCode, err := totp.GenerateCodeCustom(secret, now, totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA256,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !VerifyTOTP(LegacyTOTPMethod, secret, legacyCode, now) {
		t.Error("Expected valid legacy (SHA256) TOTP code")
	}
}

func TestKeypairRotation(t *testing.T) {
	oldKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	newKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	oldKeypair, err := NewKeypair(oldKey)
	if err != nil {
		t.Fatal(err)
	}

	token, err := oldKeypair.SignJWT(jwt.MapClaims{"sub": "1"})
	if err != nil {
		t.Fatal(err)
	}

	rotated, err := NewKeypair(newKey, &oldKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := rotated.VerifyJWT(token, jwt.MapClaims{}); err != nil {
		t.Errorf("Expected token signed with the previous key to be valid: %v", err)
	}

	withoutPrevious, _ := NewKeypair(newKey)
	if _, err := withoutPrevious.VerifyJWT(token, jwt.MapClaims{}); err == nil {
		t.Error("Expected token signed with an unknown key to be invalid")
	}

	jwks, err := rotated.JWKS()
	if err != nil {
		t.Fatal(err)
	}

	if strings.Count(string(jwks), `"kid"`) != 2 {
		t.Errorf("Expected 2 keys in the JWKS, got %s", jwks)
	}
}

package cryptography

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"regexp"
)

const CodeChallengeMethodS256 = "S256"

// RFC 7636 section 4.1: 43 to 128 characters from the unreserved set
var codeVerifierRegex = regexp.MustCompile(`^[A-Za-z0-9\-._~]{43,128}$`)

// GenerateCodeChallenge computes the PKCE code challenge of a code verifier
func GenerateCodeChallenge(method, codeVerifier string) (string, error) {
	if method != CodeChallengeMethodS256 {
		return "", unkownChallengeMethodError(method)
	}

	shaSum := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(shaSum[:]), nil
}

// VerifyCodeChallenge checks that the code verifier matches the code challenge
func VerifyCodeChallenge(method, codeChallenge, codeVerifier string) bool {
	if !codeVerifierRegex.MatchString(codeVerifier) {
		return false
	}

	challenge, err := GenerateCodeChallenge(method, codeVerifier)
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(challenge), []byte(codeChallenge)) == 1
}

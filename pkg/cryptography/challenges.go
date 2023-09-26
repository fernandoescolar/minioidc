package cryptography

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

const (
	CodeChallengeMethodPlain = "plain"
	CodeChallengeMethodS256  = "S256"
)

func GenerateCodeChallenge(method, codeVerifier string) (string, error) {
	switch method {
	case CodeChallengeMethodPlain:
		return codeVerifier, nil
	case CodeChallengeMethodS256:
		shaSum := sha256.Sum256([]byte(codeVerifier))
		return base64.RawURLEncoding.EncodeToString(shaSum[:]), nil
	default:
		return "", fmt.Errorf("unknown challenge method: %v", method)
	}
}

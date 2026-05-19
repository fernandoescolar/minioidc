package utils

import (
	"log"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/golang-jwt/jwt"
)

func ValidateJWT(t string, keypair *cryptography.Keypair, now time.Time) (*jwt.Token, bool) {
	token, err := keypair.VerifyJWT(t)
	if err != nil {
		log.Printf("Unable to verify token: %v", err)
		return nil, false
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Printf("Unable to extract token claims")
		return nil, false
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		log.Printf("Unable to extract token expiration")
		return nil, false
	}

	if now.Unix() > int64(exp) {
		log.Printf("Token expired")
		return nil, false
	}

	return token, true
}

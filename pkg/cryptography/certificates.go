package cryptography

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"

	"github.com/golang-jwt/jwt"
)

// Keypair is an RSA Keypair & JWT KeyID used for OIDC Token signing
type Keypair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Kid        string
}

// NewKeypair makes a Keypair off the provided rsa.PrivateKey or returns
// the package default if nil was passed
func NewKeypair(key *rsa.PrivateKey) (*Keypair, error) {
	if key == nil {
		panic("key cannot be nil")
	}

	return &Keypair{
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
	}, nil
}

// RandomKeypair creates a random rsa.PrivateKey and generates a key pair.
// This can be compute intensive, and should be avoided if called many
// times in a test suite.
func RandomKeypair(size int) (*Keypair, error) {
	key, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, err
	}

	return &Keypair{
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
	}, nil
}

func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	pemData, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}

	pemBlock, _ := pem.Decode(pemData)
	return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
}

// If not manually set, computes the JWT headers' `kid`
func (k *Keypair) KeyID() (string, error) {
	if k.Kid != "" {
		return k.Kid, nil
	}

	publicKeyDERBytes, err := x509.MarshalPKIXPublicKey(k.PublicKey)
	if err != nil {
		return "", err
	}

	hasher := crypto.SHA256.New()
	if _, err := hasher.Write(publicKeyDERBytes); err != nil {
		return "", err
	}
	publicKeyDERHash := hasher.Sum(nil)

	k.Kid = base64.RawURLEncoding.EncodeToString(publicKeyDERHash)

	return k.Kid, nil
}

// SignJWT signs jwt.Claims with the Keypair and returns a token string
func (k *Keypair) SignJWT(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	kid, err := k.KeyID()
	if err != nil {
		return "", err
	}
	token.Header["kid"] = kid

	return token.SignedString(k.PrivateKey)
}

// VerifyJWT verifies the signature of a token was signed with this Keypair
func (k *Keypair) VerifyJWT(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		kid, err := k.KeyID()
		if err != nil {
			return nil, err
		}
		if tk, ok := token.Header["kid"]; ok && tk == kid {
			return k.PublicKey, nil
		}
		return nil, errors.New("token kid does not match or is not present")
	})
}

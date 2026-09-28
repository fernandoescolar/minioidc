package cryptography

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

// Keypair is the RSA key used for OIDC Token signing. It also keeps the public
// keys of previous signing keys, so tokens signed before a key rotation can
// still be verified and the keys keep being published in the JWKS.
type Keypair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Kid        string

	publicKeys []publicKey
}

type publicKey struct {
	kid string
	key *rsa.PublicKey
}

type jsonWebKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// NewKeypair makes a Keypair off the provided rsa.PrivateKey. The previous
// public keys are only used to verify tokens and are published in the JWKS.
func NewKeypair(key *rsa.PrivateKey, previous ...*rsa.PublicKey) (*Keypair, error) {
	if key == nil {
		return nil, nullKeyError()
	}

	kp := &Keypair{
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
	}

	for _, pk := range append([]*rsa.PublicKey{&key.PublicKey}, previous...) {
		kid, err := keyID(pk)
		if err != nil {
			return nil, err
		}

		kp.publicKeys = append(kp.publicKeys, publicKey{kid: kid, key: pk})
	}

	kp.Kid = kp.publicKeys[0].kid
	return kp, nil
}

// LoadPrivateKey reads a PEM encoded RSA private key (PKCS#1 or PKCS#8)
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	block, err := readPEM(path)
	if err != nil {
		return nil, err
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: unsupported private key format", path)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: it is not an RSA private key", path)
	}

	return rsaKey, nil
}

// LoadPublicKey reads a PEM encoded RSA public key. A private key file is also
// accepted, so the file of a previous signing key can be used directly.
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	block, err := readPEM(path)
	if err != nil {
		return nil, err
	}

	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%s: it is not an RSA public key", path)
		}

		return rsaKey, nil
	}

	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key, nil
	}

	privateKey, err := LoadPrivateKey(path)
	if err != nil {
		return nil, err
	}

	return &privateKey.PublicKey, nil
}

func readPEM(path string) (*pem.Block, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM data found", path)
	}

	return block, nil
}

// KeyID returns the `kid` of the signing key
func (k *Keypair) KeyID() (string, error) {
	if k.Kid == "" {
		return "", nullKeyError()
	}

	return k.Kid, nil
}

// SignJWT signs jwt.Claims with the Keypair and returns a token string
func (k *Keypair) SignJWT(claims jwt.Claims, headers ...map[string]interface{}) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = k.Kid
	for _, h := range headers {
		for key, value := range h {
			token.Header[key] = value
		}
	}

	return token.SignedString(k.PrivateKey)
}

// VerifyJWT verifies the signature of a token was signed with one of the keys of this Keypair
func (k *Keypair) VerifyJWT(token string, claims jwt.Claims, opts ...jwt.ParserOption) (*jwt.Token, error) {
	opts = append(opts, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	return jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)
		for _, pk := range k.publicKeys {
			if pk.kid == kid {
				return pk.key, nil
			}
		}

		return nil, tokenKidError()
	}, opts...)
}

// JWKS returns the JSON Web Key Set with all the public keys
func (k *Keypair) JWKS() ([]byte, error) {
	keys := make([]jsonWebKey, 0, len(k.publicKeys))
	for _, pk := range k.publicKeys {
		keys = append(keys, jsonWebKey{
			Kty: "RSA",
			Use: "sig",
			Alg: jwt.SigningMethodRS256.Alg(),
			Kid: pk.kid,
			N:   base64.RawURLEncoding.EncodeToString(pk.key.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pk.key.E)).Bytes()),
		})
	}

	return json.Marshal(struct {
		Keys []jsonWebKey `json:"keys"`
	}{keys})
}

func keyID(key *rsa.PublicKey) (string, error) {
	if key == nil {
		return "", errors.New("public key cannot be nil")
	}

	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

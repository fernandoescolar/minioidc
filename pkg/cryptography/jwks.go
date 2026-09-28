package cryptography

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
)

// PublicJWK is a public key of a JSON Web Key Set
type PublicJWK struct {
	KeyID string
	Key   crypto.PublicKey
}

type rawJWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	// RSA
	N string `json:"n"`
	E string `json:"e"`
	// EC and OKP
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	// private members: a public JWKS must not have them
	D string `json:"d"`
}

// ParseJWKS reads the signature keys of a JSON Web Key Set (RFC 7517). It
// supports RSA, EC (P-256, P-384, P-521) and OKP (Ed25519) keys. Keys with
// other uses or types are ignored.
func ParseJWKS(data []byte) ([]PublicJWK, error) {
	var set struct {
		Keys []rawJWK `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("invalid JWKS: %w", err)
	}

	keys := []PublicJWK{}
	for _, raw := range set.Keys {
		if raw.Use != "" && raw.Use != "sig" {
			continue
		}

		if raw.D != "" {
			return nil, errors.New("invalid JWKS: it contains private keys")
		}

		key, err := raw.publicKey()
		if err != nil {
			return nil, err
		}

		if key != nil {
			keys = append(keys, PublicJWK{KeyID: raw.Kid, Key: key})
		}
	}

	return keys, nil
}

func (raw rawJWK) publicKey() (crypto.PublicKey, error) {
	switch raw.Kty {
	case "RSA":
		n, errN := decodeBigInt(raw.N)
		e, errE := decodeBigInt(raw.E)
		if errN != nil || errE != nil || !e.IsInt64() {
			return nil, fmt.Errorf("invalid RSA JWK %s", raw.Kid)
		}

		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		curve, ok := map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}[raw.Crv]
		x, errX := decodeBigInt(raw.X)
		y, errY := decodeBigInt(raw.Y)
		if !ok || errX != nil || errY != nil {
			return nil, fmt.Errorf("invalid EC JWK %s", raw.Kid)
		}

		key := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		// validates that the point is on the curve
		if _, err := key.ECDH(); err != nil {
			return nil, fmt.Errorf("invalid EC JWK %s: %w", raw.Kid, err)
		}

		return key, nil
	case "OKP":
		x, err := base64.RawURLEncoding.DecodeString(raw.X)
		if raw.Crv != "Ed25519" || err != nil || len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid OKP JWK %s", raw.Kid)
		}

		return ed25519.PublicKey(x), nil
	default:
		return nil, nil
	}
}

func decodeBigInt(value string) (*big.Int, error) {
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(data) == 0 {
		return nil, errors.New("invalid number")
	}

	return new(big.Int).SetBytes(data), nil
}

// LoadAnyPublicKey reads a PEM file with a public key (RSA, EC or Ed25519), certificate or private key
func LoadAnyPublicKey(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	key, err := ParsePublicKeyPEM(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	return key, nil
}

// ParsePublicKeyPEM reads a PEM public key (RSA, EC or Ed25519), certificate or private key
func ParsePublicKeyPEM(data []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM data found")
	}

	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		return cert.PublicKey, nil
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer.Public(), nil
		}
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return &key.PublicKey, nil
	}

	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return &key.PublicKey, nil
	}

	return nil, errors.New("unsupported public key format")
}

// EncodePublicKeyPEM encodes a public key as a PEM "PUBLIC KEY"
func EncodePublicKeyPEM(key crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// Package oidc implements ID token signing (RS256) and the JWKS document.
package oidc

import (
	"crypto"
	"crypto/rand"
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
)

// MinRSAKeyBits is the minimum accepted signing key size.
const MinRSAKeyBits = 2048

// Signer signs JWTs with an RSA key using RS256.
type Signer struct {
	key *rsa.PrivateKey
	kid string
}

// JWK is a public RSA JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKSet is a JSON Web Key Set.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// NewSigner wraps an RSA private key.
func NewSigner(key *rsa.PrivateKey) (*Signer, error) {
	if key == nil {
		return nil, errors.New("nil key")
	}
	if key.N.BitLen() < MinRSAKeyBits {
		return nil, fmt.Errorf("RSA key too small: %d bits (need >= %d)", key.N.BitLen(), MinRSAKeyBits)
	}
	s := &Signer{key: key}
	s.kid = thumbprint(&key.PublicKey)
	return s, nil
}

// GenerateSigner creates a signer with a fresh 2048-bit key.
func GenerateSigner() (*Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, MinRSAKeyBits)
	if err != nil {
		return nil, err
	}
	return NewSigner(key)
}

// LoadSigner reads a PEM encoded RSA private key (PKCS#1 or PKCS#8).
func LoadSigner(path string) (*Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found in signing key file")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var k any
		k, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			var ok bool
			if key, ok = k.(*rsa.PrivateKey); !ok {
				return nil, errors.New("signing key is not an RSA key")
			}
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
	if err != nil {
		return nil, err
	}
	return NewSigner(key)
}

// KeyID returns the RFC 7638 thumbprint used as "kid".
func (s *Signer) KeyID() string { return s.kid }

// PublicKey returns the public key.
func (s *Signer) PublicKey() *rsa.PublicKey { return &s.key.PublicKey }

// JWKS returns the key set containing the public key.
func (s *Signer) JWKS() JWKSet {
	return JWKSet{Keys: []JWK{publicJWK(&s.key.PublicKey, s.kid)}}
}

// Sign serialises claims and returns a compact RS256 JWS.
func (s *Signer) Sign(claims any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": s.kid})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64(header) + "." + b64(payload)
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64(sig), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func publicJWK(pub *rsa.PublicKey, kid string) JWK {
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: kid,
		Alg: "RS256",
		N:   b64(pub.N.Bytes()),
		E:   b64(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// thumbprint computes the RFC 7638 JWK SHA-256 thumbprint.
func thumbprint(pub *rsa.PublicKey) string {
	j := publicJWK(pub, "")
	// Members in lexicographic order, no whitespace.
	canonical := fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, j.E, j.N)
	sum := sha256.Sum256([]byte(canonical))
	return b64(sum[:])
}

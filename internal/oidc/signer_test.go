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
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.Sign(map[string]any{"sub": "abc", "aud": "gitea"})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[2] == "" {
		t.Fatalf("not a signed compact JWS: %q", tok)
	}
	var hdr map[string]string
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	_ = json.Unmarshal(hb, &hdr)
	if hdr["alg"] != "RS256" || hdr["kid"] != s.KeyID() {
		t.Fatalf("bad header %v", hdr)
	}

	// Verify using only the published JWKS.
	jwk := s.JWKS().Keys[0]
	nb, _ := base64.RawURLEncoding.DecodeString(jwk.N)
	eb, _ := base64.RawURLEncoding.DecodeString(jwk.E)
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil {
		t.Fatalf("signature does not verify with JWKS key: %v", err)
	}
	if jwk.Kid != s.KeyID() || jwk.Alg != "RS256" || jwk.Use != "sig" {
		t.Fatalf("bad jwk %+v", jwk)
	}
}

func TestLoadSignerPKCS8AndPKCS1(t *testing.T) {
	s, _ := GenerateSigner()
	dir := t.TempDir()
	der8, _ := x509.MarshalPKCS8PrivateKey(s.key)
	p8 := filepath.Join(dir, "k8.pem")
	_ = os.WriteFile(p8, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der8}), 0o600)
	p1 := filepath.Join(dir, "k1.pem")
	_ = os.WriteFile(p1, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(s.key)}), 0o600)
	for _, p := range []string{p8, p1} {
		l, err := LoadSigner(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if l.KeyID() != s.KeyID() {
			t.Fatalf("kid differs after reload")
		}
	}
}

func TestRejectsSmallKey(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 1024)
	if k == nil {
		t.Skip("cannot generate 1024-bit key")
	}
	if _, err := NewSigner(k); err == nil {
		t.Fatal("1024-bit key accepted")
	}
}

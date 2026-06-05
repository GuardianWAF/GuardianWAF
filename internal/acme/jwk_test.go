package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"testing"
)

// TestJWK_FixedLengthCoordinates pins the RFC 7518 requirement that EC JWK x/y
// coordinates are fixed-width (32 bytes for P-256), zero-padded — and that they
// still decode to the public key's actual coordinates. The previous
// PublicKey.X.Bytes()/Y.Bytes() encoding was variable-length and produced a wrong
// thumbprint whenever a coordinate had a leading zero byte.
func TestJWK_FixedLengthCoordinates(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	c := &Client{accountKey: key}
	jwk := c.jwk()

	for _, name := range []string{"x", "y"} {
		b, err := base64.RawURLEncoding.DecodeString(jwk[name])
		if err != nil {
			t.Fatalf("jwk[%q] is not valid base64url: %v", name, err)
		}
		if len(b) != 32 {
			t.Errorf("jwk[%q] = %d bytes, want fixed 32 (RFC 7518)", name, len(b))
		}
	}

	xb, _ := base64.RawURLEncoding.DecodeString(jwk["x"])
	yb, _ := base64.RawURLEncoding.DecodeString(jwk["y"])
	if new(big.Int).SetBytes(xb).Cmp(key.PublicKey.X) != 0 {
		t.Error("decoded x does not match public key X")
	}
	if new(big.Int).SetBytes(yb).Cmp(key.PublicKey.Y) != 0 {
		t.Error("decoded y does not match public key Y")
	}
}

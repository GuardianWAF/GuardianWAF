package acme

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// TestJWK_FixedLengthCoordinates pins the RFC 7518 requirement that EC JWK x/y
// coordinates are fixed-width (32 bytes for P-256), zero-padded — and that they
// still decode to the public key's actual coordinates.
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

	// Verify by reconstructing the EC point from the JWK coordinates and
	// comparing to the original public key via elliptic.Unmarshal.
	point := make([]byte, 65)
	point[0] = 0x04 // uncompressed point prefix
	copy(point[1:33], xb)
	copy(point[33:65], yb)
	decoded, err := ecdh.P256().NewPublicKey(point)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	expected, err := key.PublicKey.ECDH()
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}
	if !bytes.Equal(decoded.Bytes(), expected.Bytes()) {
		t.Error("decoded point does not match public key")
	}
}

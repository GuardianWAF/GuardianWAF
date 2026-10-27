package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
)

type issuerHashFixture struct {
	name        string
	issuer      *x509.Certificate
	publicValue []byte
}

func issuerHashFixtures(t *testing.T) []issuerHashFixture {
	t.Helper()
	ecPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecKey := &ecPrivate.PublicKey
	ecBytes, err := ecKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	edKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	// A fixed RSA public modulus is sufficient: hashing requires no private key.
	rsaKey := &rsa.PublicKey{N: new(big.Int).SetBytes(bytes.Repeat([]byte{0xb5}, 256)), E: 65537}
	subject, err := asn1.Marshal(pkix.Name{CommonName: "Issuer hash fixture"}.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []issuerHashFixture
	for _, tc := range []struct {
		name string
		key  any
		// Independent key encoders define the subjectPublicKey BIT STRING
		// payload, without copying the production SPKI-decoding algorithm.
		publicValue []byte
	}{
		{name: "rsa", key: rsaKey, publicValue: x509.MarshalPKCS1PublicKey(rsaKey)},
		{name: "ecdsa", key: ecKey, publicValue: ecBytes},
		{name: "ed25519", key: edKey, publicValue: []byte(edKey)},
	} {
		spki, err := x509.MarshalPKIXPublicKey(tc.key)
		if err != nil {
			t.Fatal(err)
		}
		fixtures = append(fixtures, issuerHashFixture{
			name:        tc.name,
			issuer:      &x509.Certificate{RawSubject: subject, RawSubjectPublicKeyInfo: spki},
			publicValue: tc.publicValue,
		})
	}
	return fixtures
}

func issuerHashRequest(t *testing.T, issuer *x509.Certificate) algorithmWireCertID {
	t.Helper()
	der, err := buildOCSPRequest(issuer, &x509.Certificate{SerialNumber: big.NewInt(42)})
	if err != nil {
		t.Fatal(err)
	}
	request, err := decodeAlgorithmWireRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return request.TBSRequest.Requests[0].CertID
}

func TestOCSPIssuerKeyHashUsesPublicKeyBits(t *testing.T) {
	for _, fixture := range issuerHashFixtures(t) {
		t.Run(fixture.name, func(t *testing.T) {
			id := issuerHashRequest(t, fixture.issuer)
			want := sha1.Sum(fixture.publicValue)
			if !bytes.Equal(id.KeyHash, want[:]) {
				t.Fatalf("FAIL: issuerKeyHash = %x, want SHA-1(subjectPublicKey) = %x; full SPKI must not be hashed", id.KeyHash, want)
			}
		})
	}
}

func TestOCSPIssuerNameHashAndSerialControl(t *testing.T) {
	for _, fixture := range issuerHashFixtures(t) {
		t.Run(fixture.name, func(t *testing.T) {
			id := issuerHashRequest(t, fixture.issuer)
			wantName := sha1.Sum(fixture.issuer.RawSubject)
			if !bytes.Equal(id.NameHash, wantName[:]) || id.Serial.Cmp(big.NewInt(42)) != 0 {
				t.Fatalf("FAIL: unaffected issuer-name hash or serial changed: %+v", id)
			}
		})
	}
}

func TestOCSPIssuerMalformedPublicKeyRejected(t *testing.T) {
	valid := issuerHashFixtures(t)[0].issuer.RawSubjectPublicKeyInfo
	for _, tc := range []struct {
		name string
		spki []byte
	}{
		{name: "empty"},
		{name: "invalid_der", spki: []byte{1, 2, 3}},
		{name: "trailing_der", spki: append(bytes.Clone(valid), 0, 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuer := &x509.Certificate{RawSubjectPublicKeyInfo: tc.spki}
			der, err := buildOCSPRequest(issuer, &x509.Certificate{SerialNumber: big.NewInt(42)})
			if err == nil || der != nil {
				t.Fatal("FAIL: generated a CertID from malformed issuer public-key data")
			}
		})
	}
}

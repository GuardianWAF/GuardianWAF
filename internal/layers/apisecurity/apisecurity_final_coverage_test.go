package apisecurity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type finalRoundTripFunc func(*http.Request) (*http.Response, error)

func (f finalRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type finalErrorReader struct{}

func (finalErrorReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func finalPEM(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func finalSeq(elements ...[]byte) []byte {
	var body []byte
	for _, e := range elements {
		body = append(body, e...)
	}
	return append(append([]byte{0x30}, encodeASN1Length(len(body))...), body...)
}

func TestFinalPublicKeyParsingAndConstructors(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := parsePublicKey([]byte(finalPEM(t, &k.PublicKey))); err != nil || got == nil {
			t.Fatalf("parse EC %s: %v", curve.Params().Name, err)
		}
	}
	if got, err := parsePublicKey([]byte(finalPEM(t, &rsaKey.PublicKey))); err != nil || got == nil {
		t.Fatalf("parse RSA: %v", err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if got := parseEd25519PublicKey(edPub); got == nil {
		t.Fatal("parse raw Ed25519 returned nil")
	}

	badPEMs := []string{
		"-----BEGIN PUBLIC KEY-----END PUBLIC KEY-----",
		"-----BEGIN PUBLIC KEY-----\n%%%\n-----END PUBLIC KEY-----",
		"-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----",
	}
	for _, in := range badPEMs {
		if _, err := parsePublicKey([]byte(in)); err == nil {
			t.Errorf("expected PEM error for %q", in)
		}
	}

	for _, skew := range []int{-1, 3601} {
		v, err := NewJWTValidator(JWTConfig{ClockSkewSeconds: skew})
		if err != nil {
			t.Fatal(err)
		}
		v.Stop()
	}
	if _, err := NewJWTValidator(JWTConfig{PublicKeyPEM: "bad"}); err == nil {
		t.Error("expected inline key error")
	}

	oldOpen, oldClose, oldRead := openFile, closeFile, readFile
	t.Cleanup(func() { SetFileOps(oldOpen, oldClose, oldRead) })
	SetFileOps(func(string) (any, error) { return struct{}{}, nil }, func(any) {}, func(any, []byte) (int, error) { return 0, errors.New("read") })
	if _, err := NewJWTValidator(JWTConfig{PublicKeyFile: "x"}); err == nil {
		t.Error("expected file read error")
	}
	SetFileOps(func(string) (any, error) { return nil, errors.New("open") }, func(any) {}, func(any, []byte) (int, error) { return 0, nil })
	if _, err := loadPublicKeyFromFile("x"); err == nil {
		t.Error("expected file open error")
	}
}

func TestFinalASN1ParserBranches(t *testing.T) {
	// Direct helper failures exercise every bounds/type check independently.
	for _, in := range [][]byte{{0x30, 0x80}, {0x30, 0x82, 0x01}, {0x30, 0x03, 0x02, 0x02}} {
		_, _ = parseASN1Sequence(in)
	}
	_, _, _ = parseASN1Length(nil)
	_, _ = parseASN1Elements([]byte{0x02, 0x80})
	for _, in := range [][]byte{{0x02, 0x80}, {0x02, 0x02, 0x01}, {0x02, 0x01, 0xff}} {
		_, _ = parseASN1Integer(in)
	}
	for _, in := range [][]byte{{0x03, 0x80, 0}, {0x03, 0x00, 0}} {
		_, _ = parseASN1BitString(in)
	}
	_, _ = parseASN1OID([]byte{0x06, 0x80})

	var out struct{ R, S *big.Int }
	for _, in := range [][]byte{
		{0x30, 0x05, 0x02}, {0x30, 0x00}, {0x30, 0x02, 0x02, 0x80},
		{0x30, 0x02, 0x02, 0x02}, {0x30, 0x03, 0x02, 0x01, 0x01},
		{0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x80}, {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x02, 0x01},
		{0x30, 0x81}, {0x30, 0x85, 0, 0, 0, 0, 0},
	} {
		_ = asn1Unmarshal(in, &out)
	}
	for _, in := range [][]byte{nil, {0x81}, {0x85, 0, 0, 0, 0, 0}} {
		d := append([]byte(nil), in...)
		_, _ = parseLengthFrom(&d)
	}

	// Malformed RSA structures cover each nested parse rejection.
	badRSA := [][]byte{
		finalSeq([]byte{0x02, 0x01, 0x01}),
		finalSeq([]byte{0x01, 0x01, 0x01}, []byte{0x02, 0x01, 0x03}),
		finalSeq([]byte{0x02, 0x01, 0x01}, []byte{0x01, 0x01, 0x03}),
	}
	for _, der := range badRSA {
		_ = parseRawRSAPublicKey(der)
	}
	badPKIX := [][]byte{
		finalSeq([]byte{0x01, 0x01, 0}, []byte{0x03, 0x01, 0}),
		finalSeq(finalSeq([]byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1}), []byte{0x01, 0x01, 0}),
		finalSeq(finalSeq([]byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1}), []byte{0x03, 0x02, 0, 0}),
	}
	for _, der := range badPKIX {
		_ = parsePKIXRSAPublicKey(der)
	}
}

func TestFinalJWTValidationBranches(t *testing.T) {
	secret := []byte("final-secret")
	for _, alg := range []string{"HS384", "HS512"} {
		v, _ := NewJWTValidator(JWTConfig{Algorithms: []string{alg}})
		v.hmacKeys.Store("kid", hmacKey(secret))
		hdr, _ := json.Marshal(map[string]string{"alg": alg, "kid": "kid"})
		payload, _ := json.Marshal(JWTClaims{ExpiresAt: time.Now().Add(time.Hour).Unix()})
		a := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(payload)
		// A deliberately wrong signature reaches each algorithm-specific hash branch
		// and the common constant-time mismatch path.
		if err := v.verifyHMACKey("kid", a, []byte("bad"), alg); err == nil {
			t.Error("expected bad HMAC")
		}
	}
	v := &JWTValidator{config: JWTConfig{Algorithms: []string{"HS256"}}, hmacKeys: &sync.Map{}, publicKey: []byte(secret)}
	future := JWTClaims{NotBefore: time.Now().Add(time.Hour).Unix()}
	tok, _ := GenerateToken(future, secret, "HS256")
	if _, err := v.Validate(tok); err == nil || !strings.Contains(err.Error(), "not yet") {
		t.Fatalf("not-before: %v", err)
	}
	v.publicKey = &rsa.PublicKey{N: big.NewInt(3), E: 3}
	if _, err := v.Validate(tok); err == nil || !strings.Contains(err.Error(), "not allowed with asymmetric") {
		t.Fatalf("confusion: %v", err)
	}
	v = &JWTValidator{config: JWTConfig{Algorithms: []string{"HS256"}}, hmacKeys: &sync.Map{}}
	v.hmacKeys.Store("kid", hmacKey(secret))
	badHdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"kid"}`))
	if _, err := v.Validate(badHdr + ".e30.YQ"); err == nil {
		t.Error("expected kid signature failure")
	}
}

func TestFinalJWKSAndNetworkingBranches(t *testing.T) {
	v := &JWTValidator{config: JWTConfig{JWKSURL: "http://127.0.0.1/jwks"}, log: slog.Default(), jwksCache: &sync.Map{}, hmacKeys: &sync.Map{}, stopCh: make(chan struct{}), ssrfChecked: true}
	v.client = &http.Client{Transport: finalRoundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("transport") })}
	v.fetchJWKS()
	v.client = &http.Client{Transport: finalRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(finalErrorReader{}), Header: make(http.Header)}, nil
	})}
	v.fetchJWKS()
	body := `{"keys":[{"kid":"oct","kty":"oct","k":"c2VjcmV0"},{"kid":"ec","kty":"EC","crv":"P-384","x":"AQ","y":"Ag"},{"kid":"ec2","kty":"EC","crv":"P-521","x":"AQ","y":"Ag"},{"kty":"RSA","n":"AQ","e":"Aw"}]}`
	v.client = &http.Client{Transport: finalRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	v.fetchJWKS()
	if _, ok := v.hmacKeys.Load("oct"); !ok {
		t.Error("oct key not loaded")
	}
	if err := decodeJWKSResponse(finalErrorReader{}, &struct{}{}); err == nil {
		t.Error("expected reader error")
	}
	if err := decodeJWKSResponse(bytes.NewReader(make([]byte, maxJWKSResponseBytes+1)), &struct{}{}); err == nil {
		t.Error("expected size error")
	}
	(*JWTValidator)(nil).fetchJWKS()
	(*JWTValidator)(nil).refreshJWKSPeriodically(time.Millisecond)

	v.config.JWKSURL = "://bad"
	if v.jwksPrivateAllowedForTest() {
		t.Error("bad URL allowed")
	}
	v.ssrfChecked = false
	if v.jwksPrivateAllowedForTest() {
		t.Error("unchecked allowed")
	}

	old := http.DefaultTransport
	http.DefaultTransport = finalRoundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil })
	client := v.newJWKSHTTPClient()
	http.DefaultTransport = old
	tr := client.Transport.(*http.Transport)
	_, _ = tr.DialContext(context.Background(), "tcp", "invalid.invalid:80")
	_, _ = tr.DialContext(context.Background(), "tcp", "127.0.0.1:80")
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1", nil)
	_ = client.CheckRedirect(req, nil)
}

func TestFinalDialAndRedirectBranches(t *testing.T) {
	oldIP := lookupIP
	t.Cleanup(func() { lookupIP = oldIP })
	v := &JWTValidator{config: JWTConfig{JWKSURL: "https://public.example/jwks"}}
	client := v.newJWKSHTTPClient()
	tr := client.Transport.(*http.Transport)
	lookupIP = func(string) ([]net.IP, error) { return nil, errors.New("dns") }
	if _, err := tr.DialContext(context.Background(), "tcp", "bad-address"); err == nil {
		t.Error("expected DNS error")
	}
	lookupIP = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.0.0.1")}, nil }
	if _, err := tr.DialContext(context.Background(), "tcp", "private.example:80"); err == nil {
		t.Error("expected no-public-IP error")
	}
	lookupIP = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.8")}, nil }
	_, _ = tr.DialContext(context.Background(), "tcp", "public.example:1")
	v.ssrfChecked = true
	v.config.JWKSURL = "http://localhost/jwks"
	if err := client.CheckRedirect(&http.Request{URL: mustFinalURL(t, "http://localhost/jwks")}, nil); err != nil {
		t.Fatal(err)
	}
	v.ssrfChecked = false
	if err := client.CheckRedirect(&http.Request{URL: mustFinalURL(t, "http://localhost/jwks")}, nil); err == nil {
		t.Error("expected redirect rejection")
	}
}

func mustFinalURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestFinalSignatureBranches(t *testing.T) {
	v := &JWTValidator{hmacKeys: &sync.Map{}}
	v.hmacKeys.Store("_inline", hmacKey([]byte("secret")))
	_ = v.verifySignature("HS256", "x", []byte("bad"), nil)
	v.hmacKeys.Store("_inline", "wrong")
	_ = v.verifySignature("HS256", "x", nil, nil)
	_ = verifyHMACSignatureInline(nil, "", nil, "bad")

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	digest := sha256.Sum256([]byte("data"))
	r, s, _ := ecdsa.Sign(rand.Reader, key, digest[:])
	raw := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	if err := verifyECDSASignature(&key.PublicKey, crypto.SHA256, "data", raw); err != nil {
		t.Fatal(err)
	}
	if err := verifyECDSASignature(&key.PublicKey, crypto.SHA256, "data", []byte{1}); err == nil {
		t.Error("expected format error")
	}
}

func TestFinalValidateJWKSURLPublicIP(t *testing.T) {
	if err := validateJWKSURL("https://8.8.8.8/jwks"); err != nil {
		t.Fatal(err)
	}
	if err := validateJWKSURL("https://[ff02::1]/jwks"); err == nil {
		t.Error("multicast allowed")
	}
	oldHost := lookupHost
	t.Cleanup(func() { lookupHost = oldHost })
	lookupHost = func(string) ([]string, error) { return nil, errors.New("dns") }
	if err := validateJWKSURL("https://dns.example/jwks"); err != nil {
		t.Fatal(err)
	}
	lookupHost = func(string) ([]string, error) { return []string{"not-an-ip", "10.0.0.1"}, nil }
	if err := validateJWKSURL("https://dns.example/jwks"); err == nil {
		t.Error("private DNS result allowed")
	}
	lookupHost = func(string) ([]string, error) { return []string{"not-an-ip", "8.8.8.8"}, nil }
	if err := validateJWKSURL("https://dns.example/jwks"); err != nil {
		t.Fatal(err)
	}
	_ = net.IPv4len
}

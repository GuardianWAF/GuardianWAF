package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression: Init accepted ANY EC curve via x509.ParseECPrivateKey, but the
// JWS machinery is unconditionally P-256 ("crv":"P-256", "alg":"ES256",
// 32-byte coordinate slices, 64-byte signature buffer). With a P-384/P-521
// account key (externally provisioned or hand-edited PEM), ecdsa.Sign returns
// 48-byte r/s and signedPost's sig[32-len(r):32] is a negative slice bound —
// a runtime panic at the first Register, crashing the WAF on operator input.
// Init must fail fast at the boundary with a clear error instead.
func TestInit_RejectsNonP256AccountKey(t *testing.T) {
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/directory", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"newNonce":"` + srv.URL + `/nonce","newAccount":"` + srv.URL + `/account","newOrder":"` + srv.URL + `/order"}`))
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	// A P-384 account key — parseable by x509.ParseECPrivateKey, unsupported
	// by the hardcoded ES256/P-256 JWS machinery downstream.
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	accountKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	c := NewClient(srv.URL + "/directory")
	err = c.Init(accountKeyPEM)
	if err == nil {
		t.Fatal("FAIL: Init accepted a non-P-256 account key — signedPost will panic on ES256 encoding (slice bounds out of range) at the first Register, crashing the WAF on operator input")
	}
	if !strings.Contains(err.Error(), "P-256") {
		t.Fatalf("FAIL: Init rejected the key but without the P-256 requirement in the error: %v", err)
	}
}

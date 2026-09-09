package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// Regression: a TLS listener that fails to bind (or dies at runtime) used to be
// log-only, leaving the process "healthy" while serving plaintext-only — a
// silent security downgrade. The plaintext sibling path exits non-zero; the TLS
// path must too. Forces the failure by occupying the configured TLS port before
// cmdServe starts, then asserts the stubbed osExit is requested with code 1.
func TestCmdServe_TLSListenerFailureExitsNonZero(t *testing.T) {
	dir := t.TempDir()

	// Self-signed cert pair: validateTLS requires cert/key files when TLS is
	// enabled without ACME, and buildTLSServer loads them warn-only.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatal(err)
	}

	// Occupy the TLS listen address so ListenAndServeTLS fails with
	// EADDRINUSE. Bound to a loopback port picked by the kernel.
	occ, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occ.Close()
	tlsAddr := occ.Addr().String()

	cfgPath := filepath.Join(dir, "config.yaml")
	cfgYAML := fmt.Sprintf(`listen: "127.0.0.1:0"
mode: enforce
upstreams:
  - name: default
    targets:
      - url: "http://127.0.0.1:1"
routes:
  - path: /
    upstream: default
tls:
  enabled: true
  listen: %q
  cert_file: %q
  key_file: %q
`, tlsAddr, certPath, keyPath)
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	var requested atomic.Int32
	saved := osExit
	osExit = func(code int) {
		requested.Store(int32(code))
	}
	defer func() { osExit = saved }()

	// cmdServe parses its own flags and blocks in the serve loop after
	// startup; the TLS listener failure fires during startup, the stubbed
	// osExit captures it, and the goroutine keeps serving until the test
	// process exits (ephemeral HTTP port avoids conflicts).
	go cmdServe([]string{"-c", cfgPath})

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if requested.Load() != 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := requested.Load(); got != 1 {
		t.Fatalf("osExit not requested with code 1 after TLS listener failure (got %d)", got)
	}
}

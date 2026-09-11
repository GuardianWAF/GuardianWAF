package tls

// CertStore lifecycle and boundary regression suite. Asserts the CORRECT contract;
// pins the default-cert hot-reload inclusion (finding 1) and single-label wildcard matching (finding 2) against regressions.
//
// Finding 1 (lifecycle): LoadDefaultCert stores the fallback cert outside
// cs.entries, so reloadIfChanged never hot-reloads it — a renewed fallback
// cert is invisible until process restart. Control: a non-default cert DOES
// hot-reload, proving the reload mechanism itself works.
//
// Finding 2 (boundary): wildcard SNI matching uses strings.HasSuffix without
// label boundaries, so *.example.com also matches multi-level
// a.b.example.com. RFC 6125 (and Go's crypto/tls VerifyHostname) treat "*"
// as exactly ONE label. Control: single-level a.example.com must match.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func csRegWriteCertFiles(t *testing.T, certPath, keyPath string, serial int64) (leafDER []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: fmt.Sprintf("sweep-%d", serial)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return der
}

func TestCertStoreLifecycleRegression(t *testing.T) {
	dir := t.TempDir()
	cs := NewCertStore()

	// --- Finding 1: the default/fallback cert never hot-reloads ---
	certAPath := filepath.Join(dir, "default.crt")
	keyAPath := filepath.Join(dir, "default.key")
	derA := csRegWriteCertFiles(t, certAPath, keyAPath, 100)
	if err := cs.LoadDefaultCert(certAPath, keyAPath); err != nil {
		t.Fatalf("LoadDefaultCert: %v", err)
	}

	noSNI := &tls.ClientHelloInfo{ServerName: ""}
	gotA, err := cs.GetCertificate(noSNI)
	if err != nil || gotA == nil || !bytes.Equal(gotA.Certificate[0], derA) {
		t.Fatalf("control: default cert not served initially (err=%v)", err)
	}

	// Renewal: the operator replaces the SAME files with a NEW certificate.
	derB := csRegWriteCertFiles(t, certAPath, keyAPath, 101)
	cs.reloadIfChanged()

	gotB, err := cs.GetCertificate(noSNI)
	if err != nil || gotB == nil {
		t.Fatalf("control: default cert missing after reload (err=%v)", err)
	}
	if !bytes.Equal(gotB.Certificate[0], derB) {
		t.Errorf("FAIL default-cert hot-reload: fallback still serves the OLD certificate after reloadIfChanged (LoadDefaultCert bypasses cs.entries) — got serial-derived bytes != renewed bytes")
	}

	// --- Control for the reload mechanism: a non-default cert DOES reload ---
	ctrlPath := filepath.Join(dir, "ctrl.crt")
	ctrlKeyPath := filepath.Join(dir, "ctrl.key")
	csRegWriteCertFiles(t, ctrlPath, ctrlKeyPath, 102)
	if err := cs.LoadCert([]string{"ctrl.example.com"}, ctrlPath, ctrlKeyPath); err != nil {
		t.Fatalf("LoadCert: %v", err)
	}
	derD := csRegWriteCertFiles(t, ctrlPath, ctrlKeyPath, 103)
	cs.reloadIfChanged()
	gotCtrl, err := cs.GetCertificate(&tls.ClientHelloInfo{ServerName: "ctrl.example.com"})
	if err != nil || gotCtrl == nil || !bytes.Equal(gotCtrl.Certificate[0], derD) {
		t.Errorf("control: non-default cert hot-reload broken (err=%v)", err)
	}

	// --- Finding 2: wildcard must NOT match multi-level subdomains ---
	wildPath := filepath.Join(dir, "wild.crt")
	wildKeyPath := filepath.Join(dir, "wild.key")
	wildDER := csRegWriteCertFiles(t, wildPath, wildKeyPath, 104)
	if err := cs.LoadCert([]string{"*.example.com"}, wildPath, wildKeyPath); err != nil {
		t.Fatalf("LoadCert wildcard: %v", err)
	}

	gotMulti, err := cs.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.b.example.com"})
	if err != nil {
		t.Fatalf("multi-level lookup errored: %v", err)
	}
	// CORRECT contract: the wildcard cert must NOT be served for a multi-level
	// name (RFC 6125 single-label); with a default cert configured the lookup
	// falls through to it instead.
	if bytes.Equal(gotMulti.Certificate[0], wildDER) {
		t.Errorf("FAIL wildcard-labels: *.example.com matched multi-level a.b.example.com (RFC 6125/VerifyHostname: single label only)")
	}

	// --- Control: single-level subdomain MUST match the wildcard ---
	gotSingle, err := cs.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example.com"})
	if err != nil || gotSingle == nil || !bytes.Equal(gotSingle.Certificate[0], wildDER) {
		t.Errorf("control: single-level wildcard match broken (err=%v)", err)
	}
}

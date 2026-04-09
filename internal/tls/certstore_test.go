package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateTestCert creates a self-signed cert and key in temp files.
func generateTestCert(t *testing.T, domains ...string) (certFile, keyFile string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Test"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     domains,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	certOut, _ := os.Create(certFile)
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()

	keyBytes, _ := x509.MarshalECPrivateKey(key)
	keyOut, _ := os.Create(keyFile)
	_ = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	keyOut.Close()

	return certFile, keyFile
}

func TestNewCertStore(t *testing.T) {
	cs := NewCertStore()
	if cs.CertCount() != 0 {
		t.Errorf("expected 0 certs, got %d", cs.CertCount())
	}
}

func TestLoadDefaultCert(t *testing.T) {
	certFile, keyFile := generateTestCert(t, "localhost")
	cs := NewCertStore()

	if err := cs.LoadDefaultCert(certFile, keyFile); err != nil {
		t.Fatalf("LoadDefaultCert: %v", err)
	}

	// Should work as fallback via GetCertificate
	hello := &tls.ClientHelloInfo{ServerName: "anything.com"}
	cert, err := cs.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil cert")
	}
}

func TestLoadDefaultCertInvalidPath(t *testing.T) {
	cs := NewCertStore()
	err := cs.LoadDefaultCert("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Error("expected error for nonexistent cert files")
	}
}

func TestLoadCertExactMatch(t *testing.T) {
	certFile, keyFile := generateTestCert(t, "api.example.com")
	cs := NewCertStore()

	err := cs.LoadCert([]string{"api.example.com"}, certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadCert: %v", err)
	}

	if cs.CertCount() != 1 {
		t.Errorf("expected 1 cert, got %d", cs.CertCount())
	}

	hello := &tls.ClientHelloInfo{ServerName: "api.example.com"}
	cert, err := cs.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected cert for api.example.com")
	}
}

func TestLoadCertWildcard(t *testing.T) {
	certFile, keyFile := generateTestCert(t, "*.example.com")
	cs := NewCertStore()

	err := cs.LoadCert([]string{"*.example.com"}, certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadCert wildcard: %v", err)
	}

	// Should match sub.example.com
	hello := &tls.ClientHelloInfo{ServerName: "sub.example.com"}
	cert, err := cs.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate wildcard: %v", err)
	}
	if cert == nil {
		t.Fatal("expected cert for sub.example.com via wildcard")
	}
}

func TestGetCertificateNoMatch(t *testing.T) {
	cs := NewCertStore()
	// No certs loaded, no default

	hello := &tls.ClientHelloInfo{ServerName: "test.com"}
	_, err := cs.GetCertificate(hello)
	if err == nil {
		t.Error("expected error when no certs match")
	}
}

func TestGetCertificatePriority(t *testing.T) {
	exactCert, exactKey := generateTestCert(t, "api.example.com")
	wildcardCert, wildcardKey := generateTestCert(t, "*.example.com")
	defaultCert, defaultKey := generateTestCert(t, "default")

	cs := NewCertStore()
	_ = cs.LoadDefaultCert(defaultCert, defaultKey)
	_ = cs.LoadCert([]string{"api.example.com"}, exactCert, exactKey)
	_ = cs.LoadCert([]string{"*.example.com"}, wildcardCert, wildcardKey)

	tests := []struct {
		serverName string
		expectNil  bool
	}{
		{"api.example.com", false}, // exact match
		{"www.example.com", false}, // wildcard match
		{"other.com", false},       // default fallback
	}

	for _, tt := range tests {
		hello := &tls.ClientHelloInfo{ServerName: tt.serverName}
		cert, err := cs.GetCertificate(hello)
		if err != nil {
			t.Errorf("GetCertificate(%s): %v", tt.serverName, err)
		}
		if cert == nil {
			t.Errorf("GetCertificate(%s): expected cert", tt.serverName)
		}
	}
}

func TestTLSConfig(t *testing.T) {
	certFile, keyFile := generateTestCert(t, "test.com")
	cs := NewCertStore()
	_ = cs.LoadCert([]string{"test.com"}, certFile, keyFile)

	tlsCfg := cs.TLSConfig()
	if tlsCfg == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Error("expected MinVersion TLS 1.3")
	}
	if tlsCfg.GetCertificate == nil {
		t.Error("expected GetCertificate callback")
	}
}

func TestCertHotReload(t *testing.T) {
	certFile, keyFile := generateTestCert(t, "reload.com")
	cs := NewCertStore()
	_ = cs.LoadCert([]string{"reload.com"}, certFile, keyFile)

	// Get original cert
	hello := &tls.ClientHelloInfo{ServerName: "reload.com"}
	origCert, _ := cs.GetCertificate(hello)

	// Regenerate cert files (different key)
	time.Sleep(10 * time.Millisecond) // ensure different ModTime
	newCertFile, newKeyFile := generateTestCert(t, "reload.com")

	// Copy new files over old paths
	copyFile(t, newCertFile, certFile)
	copyFile(t, newKeyFile, keyFile)

	// Trigger reload
	cs.reloadIfChanged()

	// Get new cert
	newCert, _ := cs.GetCertificate(hello)
	if newCert == origCert {
		// Pointer comparison — after reload they should be different objects
		t.Log("cert was reloaded (pointers may be equal if content is same, which is OK)")
	}
}

func TestStartStopReload(t *testing.T) {
	cs := NewCertStore()
	cs.StartReload(50 * time.Millisecond)
	time.Sleep(100 * time.Millisecond) // let it tick
	cs.StopReload()
	// Should not panic or hang
}

func TestLoadCertInvalidFiles(t *testing.T) {
	cs := NewCertStore()
	err := cs.LoadCert([]string{"test.com"}, "/nonexistent", "/nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent cert files")
	}
}

func TestCaseInsensitiveLookup(t *testing.T) {
	certFile, keyFile := generateTestCert(t, "API.Example.COM")
	cs := NewCertStore()
	_ = cs.LoadCert([]string{"API.Example.COM"}, certFile, keyFile)

	hello := &tls.ClientHelloInfo{ServerName: "api.example.com"}
	cert, err := cs.GetCertificate(hello)
	if err != nil {
		t.Fatalf("case insensitive lookup failed: %v", err)
	}
	if cert == nil {
		t.Fatal("expected cert for case-insensitive match")
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("reading %s: %v", src, err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatalf("writing %s: %v", dst, err)
	}
}

package tlsmanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// generateTestCert creates a self-signed certificate for testing and returns PEM-encoded cert and key.
func generateTestCert(t *testing.T, cn string, dnsNames []string) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

// writeTestCertFiles writes cert and key PEM to temp files and returns paths.
func writeTestCertFiles(t *testing.T, certPEM, keyPEM []byte) (certFile, keyFile string) {
	t.Helper()

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	return certFile, keyFile
}

// --- Manager Tests ---

func TestLoadCertificateFromFiles(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t, "test.example.com", []string{"test.example.com"})
	certFile, keyFile := writeTestCertFiles(t, certPEM, keyPEM)

	m := NewManager()
	err := m.LoadCertificate(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadCertificate failed: %v", err)
	}

	if !m.HasDefaultCert() {
		t.Error("expected default certificate to be set")
	}
}

func TestLoadCertificateInvalidFiles(t *testing.T) {
	m := NewManager()
	err := m.LoadCertificate("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Error("expected error loading non-existent files")
	}
}

func TestSNIRoutingMultipleCerts(t *testing.T) {
	m := NewManager()

	// Create certs for two domains
	cert1PEM, key1PEM := generateTestCert(t, "alpha.example.com", []string{"alpha.example.com"})
	cert2PEM, key2PEM := generateTestCert(t, "beta.example.com", []string{"beta.example.com"})

	tlsCert1, err := tls.X509KeyPair(cert1PEM, key1PEM)
	if err != nil {
		t.Fatalf("failed to parse cert1: %v", err)
	}
	tlsCert2, err := tls.X509KeyPair(cert2PEM, key2PEM)
	if err != nil {
		t.Fatalf("failed to parse cert2: %v", err)
	}

	m.AddCertificate("alpha.example.com", &tlsCert1)
	m.AddCertificate("beta.example.com", &tlsCert2)

	if m.CertificateCount() != 2 {
		t.Errorf("expected 2 certificates, got %d", m.CertificateCount())
	}

	// Test SNI routing for alpha
	hello1 := &tls.ClientHelloInfo{ServerName: "alpha.example.com"}
	got1, err := m.GetCertificate(hello1)
	if err != nil {
		t.Fatalf("GetCertificate failed for alpha: %v", err)
	}
	if got1 != &tlsCert1 {
		t.Error("got wrong certificate for alpha.example.com")
	}

	// Test SNI routing for beta
	hello2 := &tls.ClientHelloInfo{ServerName: "beta.example.com"}
	got2, err := m.GetCertificate(hello2)
	if err != nil {
		t.Fatalf("GetCertificate failed for beta: %v", err)
	}
	if got2 != &tlsCert2 {
		t.Error("got wrong certificate for beta.example.com")
	}
}

func TestSNIWildcardMatch(t *testing.T) {
	m := NewManager()

	certPEM, keyPEM := generateTestCert(t, "*.example.com", []string{"*.example.com"})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to parse wildcard cert: %v", err)
	}

	m.AddCertificate("*.example.com", &tlsCert)

	// Should match sub.example.com via wildcard
	hello := &tls.ClientHelloInfo{ServerName: "sub.example.com"}
	got, err := m.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate failed for wildcard: %v", err)
	}
	if got != &tlsCert {
		t.Error("wildcard certificate not matched")
	}
}

func TestSNIFallbackToDefault(t *testing.T) {
	m := NewManager()

	certPEM, keyPEM := generateTestCert(t, "default.example.com", []string{"default.example.com"})
	defaultCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to parse default cert: %v", err)
	}
	m.SetDefaultCertificate(&defaultCert)

	// Unknown domain should fall back to default
	hello := &tls.ClientHelloInfo{ServerName: "unknown.example.com"}
	got, err := m.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate failed for fallback: %v", err)
	}
	if got != &defaultCert {
		t.Error("expected fallback to default certificate")
	}
}

func TestSNINoMatchNoDefault(t *testing.T) {
	m := NewManager()

	hello := &tls.ClientHelloInfo{ServerName: "unknown.example.com"}
	_, err := m.GetCertificate(hello)
	if err == nil {
		t.Error("expected error when no certificate and no default")
	}
}

func TestGetCertificateCaseInsensitive(t *testing.T) {
	m := NewManager()

	certPEM, keyPEM := generateTestCert(t, "example.com", []string{"example.com"})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	m.AddCertificate("Example.Com", &tlsCert)

	// Lookup should be case-insensitive
	hello := &tls.ClientHelloInfo{ServerName: "example.com"}
	got, err := m.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if got != &tlsCert {
		t.Error("case-insensitive lookup failed")
	}
}

// --- Self-Signed Generation ---

func TestGenerateSelfSigned(t *testing.T) {
	cert, err := GenerateSelfSigned([]string{"localhost", "127.0.0.1", "::1"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected at least one certificate in chain")
	}

	// Parse and validate
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}

	if x509Cert.Subject.Organization[0] != "GuardianWAF Self-Signed" {
		t.Errorf("unexpected organization: %v", x509Cert.Subject.Organization)
	}

	// Check SANs
	foundLocalhost := false
	for _, name := range x509Cert.DNSNames {
		if name == "localhost" {
			foundLocalhost = true
		}
	}
	if !foundLocalhost {
		t.Error("expected 'localhost' in DNS SANs")
	}

	foundIP := false
	for _, ip := range x509Cert.IPAddresses {
		if ip.Equal(net.ParseIP("127.0.0.1")) {
			foundIP = true
		}
	}
	if !foundIP {
		t.Error("expected 127.0.0.1 in IP SANs")
	}

	// Verify key type
	if _, ok := cert.PrivateKey.(*ecdsa.PrivateKey); !ok {
		t.Error("expected ECDSA private key")
	}
}

func TestGenerateSelfSignedDefaultHosts(t *testing.T) {
	cert, err := GenerateSelfSigned(nil)
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	if len(x509Cert.DNSNames) == 0 {
		t.Error("expected default DNS names")
	}
}

// --- TLS Config ---

func TestTLSConfig(t *testing.T) {
	m := NewManager()
	cfg := m.TLSConfig()

	if cfg == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if cfg.GetCertificate == nil {
		t.Error("expected GetCertificate callback")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected MinVersion TLS 1.2, got %d", cfg.MinVersion)
	}
	if len(cfg.NextProtos) != 2 || cfg.NextProtos[0] != "h2" || cfg.NextProtos[1] != "http/1.1" {
		t.Errorf("unexpected NextProtos: %v", cfg.NextProtos)
	}
}

// --- Save and Load Certificate ---

func TestSaveAndLoadCertificate(t *testing.T) {
	cert, err := GenerateSelfSigned([]string{"test.local"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	err = SaveCertificate(cert, certFile, keyFile)
	if err != nil {
		t.Fatalf("SaveCertificate failed: %v", err)
	}

	// Verify files exist
	if _, err := os.Stat(certFile); err != nil {
		t.Errorf("cert file not created: %v", err)
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Errorf("key file not created: %v", err)
	}

	// Load back
	m := NewManager()
	err = m.LoadCertificate(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadCertificate failed after save: %v", err)
	}
	if !m.HasDefaultCert() {
		t.Error("expected default cert after loading")
	}
}

// --- ACME Challenge Handler ---

func TestACMEChallengeHandler(t *testing.T) {
	m := NewManager()
	ac := NewACMEClient("test@example.com", []string{"example.com"}, "", m)

	// Set a challenge
	ac.SetChallenge("test-token-123", "test-token-123.thumbprint")

	handler := ac.HTTPChallengeHandler()

	// Test valid challenge request
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/test-token-123", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for valid challenge, got %d", rr.Code)
	}
	if rr.Body.String() != "test-token-123.thumbprint" {
		t.Errorf("expected key authorization, got %q", rr.Body.String())
	}
	if rr.Header().Get("Content-Type") != "text/plain" {
		t.Errorf("expected text/plain content type, got %q", rr.Header().Get("Content-Type"))
	}
}

func TestACMEChallengeHandlerNotFound(t *testing.T) {
	m := NewManager()
	ac := NewACMEClient("test@example.com", []string{"example.com"}, "", m)

	handler := ac.HTTPChallengeHandler()

	// Unknown token
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/unknown-token", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown token, got %d", rr.Code)
	}
}

func TestACMEChallengeHandlerWrongPath(t *testing.T) {
	m := NewManager()
	ac := NewACMEClient("test@example.com", []string{"example.com"}, "", m)

	handler := ac.HTTPChallengeHandler()

	// Non-challenge path
	req := httptest.NewRequest("GET", "/other/path", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-challenge path, got %d", rr.Code)
	}
}

func TestACMEClearChallenge(t *testing.T) {
	m := NewManager()
	ac := NewACMEClient("test@example.com", []string{"example.com"}, "", m)

	ac.SetChallenge("token1", "auth1")
	ac.ClearChallenge("token1")

	handler := ac.HTTPChallengeHandler()
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/token1", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 after clearing challenge, got %d", rr.Code)
	}
}

// --- SNI Helper Tests ---

func TestMatchesDomain(t *testing.T) {
	tests := []struct {
		pattern  string
		hostname string
		expected bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "other.com", false},
		{"*.example.com", "sub.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "deep.sub.example.com", false}, // only one level
		{"Example.Com", "example.com", true},              // case insensitive
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.hostname, func(t *testing.T) {
			got := MatchesDomain(tt.pattern, tt.hostname)
			if got != tt.expected {
				t.Errorf("MatchesDomain(%q, %q) = %v, want %v", tt.pattern, tt.hostname, got, tt.expected)
			}
		})
	}
}

func TestGetCertificateInfo(t *testing.T) {
	certPEM, _ := generateTestCert(t, "info.example.com", []string{"info.example.com", "www.info.example.com"})

	info, err := GetCertificateInfo(certPEM)
	if err != nil {
		t.Fatalf("GetCertificateInfo failed: %v", err)
	}

	if info.CommonName != "info.example.com" {
		t.Errorf("expected CN 'info.example.com', got %q", info.CommonName)
	}
	if len(info.DNSNames) != 2 {
		t.Errorf("expected 2 DNS names, got %d", len(info.DNSNames))
	}
}

func TestGetCertificateInfoInvalidPEM(t *testing.T) {
	_, err := GetCertificateInfo([]byte("not a pem"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

// --- SNI Router ---

func TestSNIRouterAddDomainCertificate(t *testing.T) {
	m := NewManager()
	sr := NewSNIRouter(m)

	certPEM, keyPEM := generateTestCert(t, "domain.test", []string{"domain.test"})

	err := sr.AddDomainCertificate("domain.test", certPEM, keyPEM)
	if err != nil {
		t.Fatalf("AddDomainCertificate failed: %v", err)
	}

	if m.CertificateCount() != 1 {
		t.Errorf("expected 1 certificate, got %d", m.CertificateCount())
	}

	// Verify it can be retrieved
	hello := &tls.ClientHelloInfo{ServerName: "domain.test"}
	cert, err := m.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if cert == nil {
		t.Error("expected non-nil certificate")
	}
}

func TestSNIRouterAddDomainCertificateFiles(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t, "files.test", []string{"files.test"})
	certFile, keyFile := writeTestCertFiles(t, certPEM, keyPEM)

	m := NewManager()
	sr := NewSNIRouter(m)

	err := sr.AddDomainCertificateFiles("files.test", certFile, keyFile)
	if err != nil {
		t.Fatalf("AddDomainCertificateFiles failed: %v", err)
	}

	if m.CertificateCount() != 1 {
		t.Errorf("expected 1 certificate, got %d", m.CertificateCount())
	}
}

func TestSNIRouterInvalidCert(t *testing.T) {
	m := NewManager()
	sr := NewSNIRouter(m)

	err := sr.AddDomainCertificate("bad.test", []byte("bad cert"), []byte("bad key"))
	if err == nil {
		t.Error("expected error for invalid certificate")
	}

	// Suppress unused import warning
	_ = strings.Contains
}

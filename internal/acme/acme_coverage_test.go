package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- CertStatus (0% coverage) ---

func TestCoverage_CertStatus_Empty(t *testing.T) {
	store := NewCertDiskStore(t.TempDir(), nil, nil)
	status := store.CertStatus()
	if status == nil {
		t.Fatal("CertStatus should return non-nil")
	}
	if status["enabled"] != true {
		t.Error("CertStatus should have enabled=true")
	}
	if status["certs"] == nil {
		t.Error("CertStatus should have certs field")
	}
}

func TestCoverage_CertStatus_WithCerts(t *testing.T) {
	dir := t.TempDir()
	store := NewCertDiskStore(dir, nil, nil)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		DNSNames:     []string{"test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	_ = os.WriteFile(filepath.Join(dir, "test.example.com.crt"), certPEM, 0o600)
	_ = os.WriteFile(filepath.Join(dir, "test.example.com.key"), keyPEM, 0o600)

	cert, err := store.LoadOrObtain([]string{"test.example.com"})
	if err != nil {
		t.Fatalf("LoadOrObtain failed: %v", err)
	}
	_ = cert

	status := store.CertStatus()
	certs, ok := status["certs"].([]map[string]any)
	if !ok || len(certs) == 0 {
		t.Fatal("CertStatus should have certs")
	}

	first := certs[0]
	if first["domain"] != "test.example.com" {
		t.Errorf("domain = %v, want test.example.com", first["domain"])
	}
	if first["needs_renewal"] == true {
		t.Error("fresh cert should not need renewal")
	}
	if first["is_wildcard"] == true {
		t.Error("test.example.com is not a wildcard")
	}
}

func TestCoverage_CertStatus_WithNilLeaf(t *testing.T) {
	dir := t.TempDir()
	store := NewCertDiskStore(dir, nil, nil)

	cert := &tls.Certificate{
		Certificate: [][]byte{},
	}
	store.storeCert([]string{"nilleaf.example.com"}, cert)

	status := store.CertStatus()
	certs, ok := status["certs"].([]map[string]any)
	if !ok || len(certs) == 0 {
		t.Fatal("CertStatus should have certs")
	}
}

func TestCoverage_CertStatus_NearExpiry(t *testing.T) {
	dir := t.TempDir()
	store := NewCertDiskStore(dir, nil, nil)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "expiring.example.com"},
		DNSNames:     []string{"expiring.example.com"},
		NotBefore:    time.Now().Add(-60 * 24 * time.Hour),
		NotAfter:     time.Now().Add(15 * 24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	parsedCert, _ := x509.ParseCertificate(certDER)
	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		Leaf:        parsedCert,
	}
	store.storeCert([]string{"expiring.example.com"}, cert)

	status := store.CertStatus()
	certs, ok := status["certs"].([]map[string]any)
	if !ok || len(certs) == 0 {
		t.Fatal("CertStatus should have certs")
	}
	first := certs[0]
	if first["needs_renewal"] != true {
		t.Error("cert near expiry should need renewal")
	}
}

// --- allow() rate limiting ---

func TestCoverage_HTTP01Handler_RateLimit(t *testing.T) {
	h := NewHTTP01Handler()
	h.SetToken("ratelimited", "auth-value")

	w := httptest.NewRecorder()
	for i := 0; i < 15; i++ {
		r := httptest.NewRequest("GET", "/.well-known/acme-challenge/ratelimited", nil)
		r.RemoteAddr = "10.0.0.1:12345"
		h.ServeHTTP(w, r)
	}
	t.Logf("Last response code: %d", w.Code)
}

func TestCoverage_HTTP01Handler_Allow_LargeMap(t *testing.T) {
	h := NewHTTP01Handler()
	for i := 0; i < 1100; i++ {
		ip := "10.0." + string(rune('0'+i/256)) + "." + string(rune('0'+i%256))
		r := httptest.NewRequest("GET", "/.well-known/acme-challenge/test", nil)
		r.RemoteAddr = ip + ":12345"
		h.allow(r)
	}
}

func TestCoverage_HTTP01Handler_Allow_WithPort(t *testing.T) {
	h := NewHTTP01Handler()
	r := httptest.NewRequest("GET", "/.well-known/acme-challenge/test", nil)
	r.RemoteAddr = "192.168.1.1:54321"
	allowed := h.allow(r)
	if !allowed {
		t.Error("first request should be allowed")
	}
}

// --- LoadOrObtain edge cases ---

func TestCoverage_LoadOrObtain_NoDomains(t *testing.T) {
	store := NewCertDiskStore(t.TempDir(), nil, nil)
	_, err := store.LoadOrObtain([]string{})
	if err == nil {
		t.Error("LoadOrObtain with empty domains should fail")
	}
}

func TestCoverage_LoadOrObtain_CachedCertParseError(t *testing.T) {
	dir := t.TempDir()

	_ = os.WriteFile(filepath.Join(dir, "bad.example.com.crt"), []byte("not a cert"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "bad.example.com.key"), []byte("not a key"), 0o600)

	var dirSrv *httptest.Server
	dirSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(directory{
			NewNonce:   dirSrv.URL + "/nonce",
			NewAccount: dirSrv.URL + "/account",
			NewOrder:   dirSrv.URL + "/order",
		})
	}))
	defer dirSrv.Close()

	client := NewClient(dirSrv.URL)
	if err := client.Init(nil); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	handler := NewHTTP01Handler()
	store := NewCertDiskStore(dir, client, handler)

	_, err := store.LoadOrObtain([]string{"bad.example.com"})
	if err == nil {
		t.Error("LoadOrObtain with bad cert data should fail")
	}
}

func TestCoverage_RenewIfNeeded_EmptyDomains(t *testing.T) {
	store := NewCertDiskStore(t.TempDir(), nil, nil)
	store.AddDomains([]string{})
	store.renewIfNeeded()
}

// --- StopRenewal idempotent ---

func TestCoverage_StopRenewal_Twice(t *testing.T) {
	store := NewCertDiskStore(t.TempDir(), nil, nil)
	store.StopRenewal()
	store.StopRenewal()
}

// --- sanitizeDomain edge cases ---

func TestCoverage_SanitizeDomain_EdgeCases(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"test..example.com", "test_example.com"},
		{"test/example", "test_example"},
		{"test:8080", "test_8080"},
		{"test\x00null", "testnull"},
		{"", "_invalid_"},
		{"!!!", "_invalid_"},
	}

	for _, tt := range tests {
		got := sanitizeDomain(tt.input)
		if got != tt.expected {
			t.Errorf("sanitizeDomain(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// --- createCSR empty domains ---

func TestCoverage_CreateCSR_EmptyDomains(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := createCSR(key, []string{})
	if err == nil {
		t.Error("createCSR with empty domains should fail")
	}
}

// --- Client Init with bad PEM ---

func TestCoverage_Init_BadECKey(t *testing.T) {
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("not a valid key")})

	var dirSrv *httptest.Server
	dirSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(directory{
			NewNonce:   dirSrv.URL + "/nonce",
			NewAccount: dirSrv.URL + "/account",
			NewOrder:   dirSrv.URL + "/order",
		})
	}))
	defer dirSrv.Close()

	c := NewClient(dirSrv.URL)
	err := c.Init(badPEM)
	if err == nil {
		t.Error("Init with bad EC key should fail")
	}
}

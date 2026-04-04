package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

// --- HTTP01Handler Tests ---

func TestHTTP01Handler(t *testing.T) {
	h := NewHTTP01Handler()

	// No token yet
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/.well-known/acme-challenge/mytoken", nil)
	h.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Errorf("expected 404 without token, got %d", w.Code)
	}

	// Set token
	h.SetToken("mytoken", "mytoken.thumbprint123")

	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/.well-known/acme-challenge/mytoken", nil)
	h.ServeHTTP(w2, r2)
	if w2.Code != 200 {
		t.Errorf("expected 200, got %d", w2.Code)
	}
	if w2.Body.String() != "mytoken.thumbprint123" {
		t.Errorf("expected key auth, got %q", w2.Body.String())
	}

	// Clear token
	h.ClearToken("mytoken")

	w3 := httptest.NewRecorder()
	r3 := httptest.NewRequest("GET", "/.well-known/acme-challenge/mytoken", nil)
	h.ServeHTTP(w3, r3)
	if w3.Code != 404 {
		t.Errorf("expected 404 after clear, got %d", w3.Code)
	}
}

func TestHTTP01HandlerWrongPath(t *testing.T) {
	h := NewHTTP01Handler()
	h.SetToken("tok", "auth")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/other/path", nil)
	h.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Errorf("expected 404 for wrong path, got %d", w.Code)
	}
}

func TestHTTP01HandlerEmptyToken(t *testing.T) {
	h := NewHTTP01Handler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/.well-known/acme-challenge/", nil)
	h.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Errorf("expected 404 for empty token, got %d", w.Code)
	}
}

// --- Client Tests ---

func TestNewClient(t *testing.T) {
	c := NewClient(LetsEncryptStaging)
	if c.directoryURL != LetsEncryptStaging {
		t.Errorf("expected staging URL")
	}
}

func TestClientInitGeneratesKey(t *testing.T) {
	// Mock directory server
	dirSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(directory{
			NewNonce:   "http://localhost/nonce",
			NewAccount: "http://localhost/account",
			NewOrder:   "http://localhost/order",
		})
	}))
	defer dirSrv.Close()

	c := NewClient(dirSrv.URL)
	err := c.Init(nil)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if c.accountKey == nil {
		t.Error("expected generated account key")
	}
}

func TestClientInitLoadsKey(t *testing.T) {
	// Generate a key
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	dirSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(directory{
			NewNonce:   "http://localhost/nonce",
			NewAccount: "http://localhost/account",
			NewOrder:   "http://localhost/order",
		})
	}))
	defer dirSrv.Close()

	c := NewClient(dirSrv.URL)
	err := c.Init(keyPEM)
	if err != nil {
		t.Fatalf("Init with key: %v", err)
	}
	if c.accountKey == nil {
		t.Error("expected loaded account key")
	}
}

func TestClientAccountKeyPEM(t *testing.T) {
	dirSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(directory{
			NewNonce:   "http://localhost/nonce",
			NewAccount: "http://localhost/account",
			NewOrder:   "http://localhost/order",
		})
	}))
	defer dirSrv.Close()

	c := NewClient(dirSrv.URL)
	_ = c.Init(nil)

	pemData, err := c.AccountKeyPEM()
	if err != nil {
		t.Fatalf("AccountKeyPEM: %v", err)
	}
	if len(pemData) == 0 {
		t.Error("expected non-empty PEM")
	}

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		t.Error("expected valid EC PRIVATE KEY PEM block")
	}
}

func TestClientInitInvalidKey(t *testing.T) {
	dirSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(directory{})
	}))
	defer dirSrv.Close()

	c := NewClient(dirSrv.URL)
	err := c.Init([]byte("not a valid PEM"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

// --- CertDiskStore Tests ---

func generateSelfSignedCert(t *testing.T, domain string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

func TestCertDiskStoreLoadCached(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := generateSelfSignedCert(t, "test.com")

	// Pre-populate cache
	_ = os.WriteFile(filepath.Join(dir, "test.com.crt"), certPEM, 0o600)
	_ = os.WriteFile(filepath.Join(dir, "test.com.key"), keyPEM, 0o600)

	store := NewCertDiskStore(dir, nil, nil)
	cert, err := store.LoadOrObtain([]string{"test.com"})
	if err != nil {
		t.Fatalf("LoadOrObtain: %v", err)
	}
	if cert == nil {
		t.Fatal("expected cert")
	}

	// Should be cached
	cached, ok := store.GetCert("test.com")
	if !ok || cached == nil {
		t.Error("expected cached cert")
	}
}

func TestCertDiskStoreSanitizeDomain(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"example.com", "example.com"},
		{"*.example.com", "_wildcard_.example.com"},
		{"SUB.Example.COM", "sub.example.com"},
	}
	for _, tt := range tests {
		got := sanitizeDomain(tt.input)
		if got != tt.expected {
			t.Errorf("sanitizeDomain(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestCertDiskStoreAddDomains(t *testing.T) {
	store := NewCertDiskStore(t.TempDir(), nil, nil)
	store.AddDomains([]string{"a.com", "b.com"})
	store.AddDomains([]string{"c.com"})
	if len(store.domains) != 2 {
		t.Errorf("expected 2 domain groups, got %d", len(store.domains))
	}
}

func TestSplitDomains(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"a.com,b.com", []string{"a.com", "b.com"}},
		{"  a.com , b.com  ", []string{"a.com", "b.com"}},
		{"single.com", []string{"single.com"}},
		{"", nil},
	}
	for _, tt := range tests {
		got := SplitDomains(tt.input)
		if len(got) != len(tt.expected) {
			t.Errorf("SplitDomains(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestFileExists(t *testing.T) {
	f := filepath.Join(t.TempDir(), "test.txt")
	if fileExists(f) {
		t.Error("should not exist yet")
	}
	_ = os.WriteFile(f, []byte("hi"), 0o644)
	if !fileExists(f) {
		t.Error("should exist after write")
	}
}

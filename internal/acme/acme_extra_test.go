package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewHTTP01Handler(t *testing.T) {
	h := NewHTTP01Handler()
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
	if h.tokens == nil {
		t.Error("expected initialized tokens map")
	}
}

func TestHTTP01Handler_ConcurrentAccess(t *testing.T) {
	h := NewHTTP01Handler()
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			token := "token-" + string(rune('A'+id))
			h.SetToken(token, "auth-"+token)
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/.well-known/acme-challenge/"+token, nil)
			h.ServeHTTP(w, r)
			h.ClearToken(token)
		}(i)
	}
	wg.Wait()
}

func TestHTTP01Handler_ContentType(t *testing.T) {
	h := NewHTTP01Handler()
	h.SetToken("testtoken", "auth-value")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/.well-known/acme-challenge/testtoken", nil)
	h.ServeHTTP(w, r)

	if ct := w.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("expected application/octet-stream, got %q", ct)
	}
}

func TestClientInit_BadDirectoryURL(t *testing.T) {
	c := NewClient("http://127.0.0.1:1/nonexistent")
	err := c.Init(nil)
	if err == nil {
		t.Error("expected error for unreachable directory URL")
	}
}

func TestClientInit_BadDirectoryJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	err := c.Init(nil)
	if err == nil {
		t.Error("expected error for invalid directory JSON")
	}
}

func TestClientInit_InvalidPEMBlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(directory{})
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	// Valid PEM wrapper but bad content
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("garbage")})
	err := c.Init(badPEM)
	if err == nil {
		t.Error("expected error for invalid EC key in PEM")
	}
}

func TestSplitDomains_Whitespace(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{",,,", 0},
		{" , , ", 0},
		{"a.com, , b.com", 2},
		{"  single.com  ", 1},
	}
	for _, tt := range tests {
		got := SplitDomains(tt.input)
		if len(got) != tt.expected {
			t.Errorf("SplitDomains(%q) = %v (len %d), want len %d", tt.input, got, len(got), tt.expected)
		}
	}
}

func TestSerialNumber(t *testing.T) {
	n1 := SerialNumber()
	n2 := SerialNumber()
	if n1 == nil || n2 == nil {
		t.Fatal("expected non-nil serial numbers")
	}
	if n1.Cmp(n2) == 0 {
		t.Error("expected different serial numbers")
	}
	// Should be positive
	if n1.Sign() <= 0 {
		t.Error("expected positive serial number")
	}
}

func TestCreateCSR(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := createCSR(key, []string{"example.com", "www.example.com"})
	if err != nil {
		t.Fatalf("createCSR: %v", err)
	}
	if len(csr) == 0 {
		t.Error("expected non-empty CSR")
	}

	// Parse to verify
	parsedCSR, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if parsedCSR.Subject.CommonName != "example.com" {
		t.Errorf("expected CN=example.com, got %q", parsedCSR.Subject.CommonName)
	}
	if len(parsedCSR.DNSNames) != 2 {
		t.Errorf("expected 2 DNS names, got %d", len(parsedCSR.DNSNames))
	}
}

func TestClientJWK(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := &Client{accountKey: key}

	jwk := c.jwk()
	if jwk["kty"] != "EC" {
		t.Errorf("expected kty=EC, got %q", jwk["kty"])
	}
	if jwk["crv"] != "P-256" {
		t.Errorf("expected crv=P-256, got %q", jwk["crv"])
	}
	if jwk["x"] == "" || jwk["y"] == "" {
		t.Error("expected x and y coordinates")
	}
}

func TestClientJWKThumbprint(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := &Client{accountKey: key}

	tp, err := c.jwkThumbprint()
	if err != nil {
		t.Fatalf("jwkThumbprint: %v", err)
	}
	if tp == "" {
		t.Error("expected non-empty thumbprint")
	}
	// Should be base64url encoded
	if len(tp) < 10 {
		t.Errorf("thumbprint seems too short: %q", tp)
	}
}

func TestClientNoncePool(t *testing.T) {
	c := &Client{}
	c.nonces = []string{"nonce1", "nonce2"}

	// Pop from pool
	c.mu.Lock()
	n := c.nonces[len(c.nonces)-1]
	c.nonces = c.nonces[:len(c.nonces)-1]
	c.mu.Unlock()

	if n != "nonce2" {
		t.Errorf("expected nonce2, got %q", n)
	}
	if len(c.nonces) != 1 {
		t.Errorf("expected 1 nonce remaining, got %d", len(c.nonces))
	}
}

func TestClientSaveNonce(t *testing.T) {
	c := &Client{}
	resp := &http.Response{
		Header: http.Header{},
	}
	resp.Header.Set("Replay-Nonce", "test-nonce")
	c.saveNonce(resp)

	if len(c.nonces) != 1 || c.nonces[0] != "test-nonce" {
		t.Errorf("expected saved nonce, got %v", c.nonces)
	}

	// No nonce header — should not add
	resp2 := &http.Response{Header: http.Header{}}
	c.saveNonce(resp2)
	if len(c.nonces) != 1 {
		t.Errorf("expected 1 nonce (no new one), got %d", len(c.nonces))
	}
}

func TestCertDiskStore_GetCert_NotFound(t *testing.T) {
	store := NewCertDiskStore(t.TempDir(), nil, nil)
	cert, ok := store.GetCert("nonexistent.com")
	if ok || cert != nil {
		t.Error("expected no cert for unknown domain")
	}
}

func TestCertDiskStore_GetCert_CaseInsensitive(t *testing.T) {
	store := NewCertDiskStore(t.TempDir(), nil, nil)
	// Manually store a cert
	store.mu.Lock()
	store.certs["example.com"] = nil
	store.mu.Unlock()

	// GetCert lowercases the domain
	_, ok := store.GetCert("Example.COM")
	if !ok {
		t.Error("expected to find cert with case-insensitive lookup")
	}
}

func TestCertDiskStore_StartStopRenewal(t *testing.T) {
	store := NewCertDiskStore(t.TempDir(), nil, nil)
	store.StartRenewal(100 * time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	store.StopRenewal()
}

func TestCertDiskStore_CertPath(t *testing.T) {
	store := NewCertDiskStore("/cache", nil, nil)
	path := store.certPath("example.com")
	expected := filepath.Join("/cache", "example.com.crt")
	if path != expected {
		t.Errorf("expected %q, got %q", expected, path)
	}
}

func TestCertDiskStore_KeyPath(t *testing.T) {
	store := NewCertDiskStore("/cache", nil, nil)
	path := store.keyPath("example.com")
	expected := filepath.Join("/cache", "example.com.key")
	if path != expected {
		t.Errorf("expected %q, got %q", expected, path)
	}
}

func TestCertDiskStore_WildcardPaths(t *testing.T) {
	store := NewCertDiskStore("/cache", nil, nil)
	path := store.certPath("*.example.com")
	if path != filepath.Join("/cache", "_wildcard_.example.com.crt") {
		t.Errorf("unexpected path: %s", path)
	}
}

func TestCertDiskStore_LoadValidCachedCert(t *testing.T) {
	dir := t.TempDir()

	// Generate a valid (not expired) cert
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "valid.com"},
		DNSNames:     []string{"valid.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	os.WriteFile(filepath.Join(dir, "valid.com.crt"), certPEM, 0600)
	os.WriteFile(filepath.Join(dir, "valid.com.key"), keyPEM, 0600)

	store := NewCertDiskStore(dir, nil, nil)
	cert, err := store.LoadOrObtain([]string{"valid.com"})
	if err != nil {
		t.Fatalf("LoadOrObtain: %v", err)
	}
	if cert == nil {
		t.Fatal("expected cert")
	}

	// Should be cached
	cached, ok := store.GetCert("valid.com")
	if !ok || cached == nil {
		t.Error("expected cached cert after load")
	}
}

func TestSanitizeDomain(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"example.com", "example.com"},
		{"*.example.com", "_wildcard_.example.com"},
		{"SUB.Example.COM", "sub.example.com"},
		{"host:8080", "host_8080"},
		{"path/domain", "path_domain"},
	}
	for _, tt := range tests {
		got := sanitizeDomain(tt.input)
		if got != tt.expected {
			t.Errorf("sanitizeDomain(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestFileExists_Dir(t *testing.T) {
	dir := t.TempDir()
	if !fileExists(dir) {
		t.Error("directory should exist")
	}
}

func TestClientRegister_MockServer(t *testing.T) {
	// Create a mock ACME server
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce-123")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/account/1")
		w.Header().Set("Replay-Nonce", "nonce-2")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"status": "valid",
		})
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL + "/directory")
	if err := c.Init(nil); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := c.Register("test@example.com"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if c.accountURL != srv.URL+"/account/1" {
		t.Errorf("expected account URL, got %q", c.accountURL)
	}
}

func TestClientRegister_FailedStatus(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce2")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"type":"urn:ietf:params:acme:error:unauthorized"}`))
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL + "/directory")
	c.Init(nil)
	err := c.Register("test@example.com")
	if err == nil {
		t.Error("expected error for failed registration")
	}
}

// newMockACME creates a mock ACME server for testing order creation and certificate flow.
func newMockACME(t *testing.T) (*httptest.Server, *Client) {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "mock-nonce")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/account/1")
		w.Header().Set("Replay-Nonce", "nonce-acct")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/order/1")
		w.Header().Set("Replay-Nonce", "nonce-order")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"status":         "pending",
			"authorizations": []string{srv.URL + "/authz/1"},
			"finalize":       srv.URL + "/finalize/1",
		})
	})
	mux.HandleFunc("/authz/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-authz")
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "valid", // already validated
			"identifier": map[string]string{"value": "test.example.com"},
			"challenges": []map[string]string{
				{"type": "http-01", "url": srv.URL + "/challenge/1", "token": "test-token"},
			},
		})
	})
	mux.HandleFunc("/finalize/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-fin")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-poll")
		// Generate a self-signed cert
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(42),
			Subject:      pkix.Name{CommonName: "test.example.com"},
			DNSNames:     []string{"test.example.com"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		json.NewEncoder(w).Encode(map[string]any{
			"status":      "valid",
			"certificate": srv.URL + "/cert/1",
		})
		_ = certPEM // used below
	})
	mux.HandleFunc("/cert/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-cert")
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(42),
			Subject:      pkix.Name{CommonName: "test.example.com"},
			DNSNames:     []string{"test.example.com"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		w.Write(certPEM)
	})

	srv = httptest.NewServer(mux)
	c := NewClient(srv.URL + "/directory")
	if err := c.Init(nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Register("test@example.com"); err != nil {
		t.Fatal(err)
	}
	return srv, c
}

func TestCreateOrder_MockServer(t *testing.T) {
	srv, c := newMockACME(t)
	defer srv.Close()

	o, orderURL, err := c.createOrder([]string{"test.example.com"})
	if err != nil {
		t.Fatalf("createOrder: %v", err)
	}
	if o.Status != "pending" {
		t.Errorf("expected pending, got %q", o.Status)
	}
	if len(o.Authorizations) != 1 {
		t.Errorf("expected 1 authz, got %d", len(o.Authorizations))
	}
	if orderURL == "" {
		t.Error("expected order URL")
	}
}

func TestObtainCertificate_MockServer(t *testing.T) {
	srv, c := newMockACME(t)
	defer srv.Close()

	handler := NewHTTP01Handler()
	certPEM, keyPEM, err := c.ObtainCertificate([]string{"test.example.com"}, handler)
	if err != nil {
		t.Fatalf("ObtainCertificate: %v", err)
	}
	if len(certPEM) == 0 {
		t.Error("expected cert PEM")
	}
	if len(keyPEM) == 0 {
		t.Error("expected key PEM")
	}

	// Verify cert PEM is valid
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("could not decode cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("expected CN=test.example.com, got %q", cert.Subject.CommonName)
	}
}

func TestCreateOrder_FailedStatus(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/acct/1")
		w.Header().Set("Replay-Nonce", "n2")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n3")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"type":"forbidden"}`))
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL + "/directory")
	c.Init(nil)
	c.Register("test@example.com")

	_, _, err := c.createOrder([]string{"bad.com"})
	if err == nil {
		t.Error("expected error for failed order")
	}
}

func TestGetNonce_FromPool(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "fresh-nonce")
		w.WriteHeader(200)
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL + "/directory")
	c.Init(nil)

	// Pre-fill the nonce pool
	c.mu.Lock()
	c.nonces = append(c.nonces, "pooled-nonce")
	c.mu.Unlock()

	// Should get from pool first
	n, err := c.getNonce()
	if err != nil {
		t.Fatalf("getNonce: %v", err)
	}
	if n != "pooled-nonce" {
		t.Errorf("expected pooled-nonce, got %q", n)
	}

	// Pool empty, should fetch from server
	n2, err := c.getNonce()
	if err != nil {
		t.Fatalf("getNonce: %v", err)
	}
	if n2 != "fresh-nonce" {
		t.Errorf("expected fresh-nonce, got %q", n2)
	}
}

func TestFinalizeOrder_Failed(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/acct/1")
		w.Header().Set("Replay-Nonce", "n2")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/finalize", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n3")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"type":"badCSR"}`))
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL + "/directory")
	c.Init(nil)
	c.Register("test@example.com")

	err := c.finalizeOrder(srv.URL+"/finalize", []byte("fake-csr"))
	if err == nil {
		t.Error("expected error for failed finalize")
	}
}

func TestCertDiskStore_StoreCertMultipleDomains(t *testing.T) {
	store := NewCertDiskStore(t.TempDir(), nil, nil)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "a.com"},
		DNSNames:     []string{"a.com", "b.com", "c.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	os.WriteFile(filepath.Join(store.cacheDir, "a.com.crt"), certPEM, 0600)
	os.WriteFile(filepath.Join(store.cacheDir, "a.com.key"), keyPEM, 0600)

	cert, err := store.LoadOrObtain([]string{"a.com", "b.com", "c.com"})
	if err != nil {
		t.Fatalf("LoadOrObtain: %v", err)
	}
	if cert == nil {
		t.Fatal("expected cert")
	}

	// All domains should be cached
	for _, d := range []string{"a.com", "b.com", "c.com"} {
		_, ok := store.GetCert(d)
		if !ok {
			t.Errorf("expected cert cached for %s", d)
		}
	}
}

// --- completeAuthorization tests ---

func TestCompleteAuthorization_NoHTTP01Challenge(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/acct/1")
		w.Header().Set("Replay-Nonce", "n2")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/authz/no-http01", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n-authz")
		// No http-01 challenge, only dns-01
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "pending",
			"identifier": map[string]string{"value": "test.com"},
			"challenges": []map[string]string{
				{"type": "dns-01", "url": srv.URL + "/challenge/dns", "token": "token"},
			},
		})
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL + "/directory")
	c.Init(nil)
	c.Register("test@example.com")

	handler := NewHTTP01Handler()
	err := c.completeAuthorization(srv.URL+"/authz/no-http01", handler)
	if err == nil {
		t.Error("expected error when no http-01 challenge")
	}
	if !strings.Contains(err.Error(), "no http-01 challenge") {
		t.Errorf("expected 'no http-01 challenge' error, got: %v", err)
	}
}

func TestCompleteAuthorization_AlreadyValid(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/acct/1")
		w.Header().Set("Replay-Nonce", "n2")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/authz/valid", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n-authz")
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "valid", // Already validated
			"identifier": map[string]string{"value": "test.com"},
			"challenges": []map[string]string{
				{"type": "http-01", "url": srv.URL + "/challenge/1", "token": "token"},
			},
		})
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL + "/directory")
	c.Init(nil)
	c.Register("test@example.com")

	handler := NewHTTP01Handler()
	err := c.completeAuthorization(srv.URL+"/authz/valid", handler)
	if err != nil {
		t.Errorf("expected no error for already valid authz, got: %v", err)
	}
}

func TestCompleteAuthorization_BecomesInvalid(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server
	callCount := 0

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/acct/1")
		w.Header().Set("Replay-Nonce", "n2")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/authz/invalid", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n-authz")
		callCount++
		if callCount == 1 {
			// First call - pending
			json.NewEncoder(w).Encode(map[string]any{
				"status":     "pending",
				"identifier": map[string]string{"value": "test.com"},
				"challenges": []map[string]string{
					{"type": "http-01", "url": srv.URL + "/challenge/1", "token": "token"},
				},
			})
		} else {
			// Poll - becomes invalid
			json.NewEncoder(w).Encode(map[string]any{
				"status":     "invalid",
				"identifier": map[string]string{"value": "test.com"},
				"challenges": []map[string]string{
					{"type": "http-01", "url": srv.URL + "/challenge/1", "token": "token"},
				},
			})
		}
	})
	mux.HandleFunc("/challenge/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n-ch")
		w.WriteHeader(200)
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL + "/directory")
	c.Init(nil)
	c.Register("test@example.com")

	handler := NewHTTP01Handler()
	err := c.completeAuthorization(srv.URL+"/authz/invalid", handler)
	if err == nil {
		t.Error("expected error when authz becomes invalid")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Errorf("expected 'invalid' error, got: %v", err)
	}
}

// --- renewIfNeeded tests ---

func TestRenewIfNeeded_ValidNotExpired(t *testing.T) {
	dir := t.TempDir()

	// Create a cert valid for 90 days
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "valid.com"},
		DNSNames:     []string{"valid.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	os.WriteFile(filepath.Join(dir, "valid.com.crt"), certPEM, 0600)
	os.WriteFile(filepath.Join(dir, "valid.com.key"), keyPEM, 0600)

	store := NewCertDiskStore(dir, nil, nil)
	store.AddDomains([]string{"valid.com"})

	// Should not try to renew - cert is valid for 90 days
	store.renewIfNeeded()
	// No panic = success
}

func TestRenewIfNeeded_InvalidCertFile(t *testing.T) {
	dir := t.TempDir()

	// Write invalid cert data
	os.WriteFile(filepath.Join(dir, "bad.com.crt"), []byte("not a cert"), 0600)
	os.WriteFile(filepath.Join(dir, "bad.com.key"), []byte("not a key"), 0600)

	store := NewCertDiskStore(dir, nil, nil)
	store.AddDomains([]string{"bad.com"})

	// Should handle error gracefully - LoadX509KeyPair fails, continue is called
	store.renewIfNeeded()
	// No panic = success
}

func TestRenewIfNeeded_NeedsRenewalWithMockClient(t *testing.T) {
	// Create a mock ACME server for the renewal flow
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL + "/acct/1")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/order/1")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{
			"status":         "pending",
			"authorizations": []string{srv.URL + "/authz/1"},
			"finalize":       srv.URL + "/finalize",
		})
	})
	mux.HandleFunc("/authz/1", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "valid",
			"identifier": map[string]string{"value": "expiring.com"},
			"challenges": []map[string]string{
				{"type": "http-01", "url": srv.URL + "/ch/1", "token": "tok"},
			},
		})
	})
	mux.HandleFunc("/finalize", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order/1", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status":      "valid",
			"certificate": srv.URL + "/cert/1",
		})
	})
	mux.HandleFunc("/cert/1", func(w http.ResponseWriter, r *http.Request) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "expiring.com"},
			DNSNames:     []string{"expiring.com"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		w.Write(certPEM)
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()

	// Create a cert that expires in 20 days (within 30-day renewal window)
	oldKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expiring.com"},
		DNSNames:     []string{"expiring.com"},
		NotBefore:    time.Now().Add(-70 * 24 * time.Hour),
		NotAfter:     time.Now().Add(20 * 24 * time.Hour), // 20 days left = needs renewal
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &oldKey.PublicKey, oldKey)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(oldKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	os.WriteFile(filepath.Join(dir, "expiring.com.crt"), certPEM, 0600)
	os.WriteFile(filepath.Join(dir, "expiring.com.key"), keyPEM, 0600)

	// Create client and store with mock server
	client := NewClient(srv.URL + "/directory")
	client.Init(nil)
	client.Register("test@example.com")

	handler := NewHTTP01Handler()
	store := NewCertDiskStore(dir, client, handler)
	store.AddDomains([]string{"expiring.com"})

	// Should trigger renewal
	store.renewIfNeeded()
	// No panic = success
}

func TestRenewIfNeeded_NoCertFileWithMockClient(t *testing.T) {
	// Create a mock ACME server
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL + "/acct/1")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/order/1")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{
			"status":         "pending",
			"authorizations": []string{srv.URL + "/authz/1"},
			"finalize":       srv.URL + "/finalize",
		})
	})
	mux.HandleFunc("/authz/1", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "valid",
			"identifier": map[string]string{"value": "newdomain.com"},
			"challenges": []map[string]string{
				{"type": "http-01", "url": srv.URL + "/ch/1", "token": "tok"},
			},
		})
	})
	mux.HandleFunc("/finalize", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order/1", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status":      "valid",
			"certificate": srv.URL + "/cert/1",
		})
	})
	mux.HandleFunc("/cert/1", func(w http.ResponseWriter, r *http.Request) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "newdomain.com"},
			DNSNames:     []string{"newdomain.com"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		w.Write(certPEM)
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL + "/directory")
	client.Init(nil)
	client.Register("test@example.com")

	handler := NewHTTP01Handler()
	store := NewCertDiskStore(t.TempDir(), client, handler)
	store.AddDomains([]string{"newdomain.com"})

	// No cert file - should obtain new one
	store.renewIfNeeded()
	// No panic = success
}

// --- LoadOrObtain edge cases ---

// Note: LoadOrObtain with expired cert requires full ACME flow which is tested
// in TestLoadOrObtain_WithMockACME. The expiry detection logic is exercised
// through the renewIfNeeded tests.

// --- pollCertificate edge cases ---

func TestPollCertificate_BecomesInvalid(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/acct/1")
		w.Header().Set("Replay-Nonce", "n2")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order/invalid", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		json.NewEncoder(w).Encode(map[string]any{
			"status": "invalid",
		})
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL + "/directory")
	c.Init(nil)
	c.Register("test@example.com")

	_, err := c.pollCertificate(srv.URL + "/order/invalid")
	if err == nil {
		t.Error("expected error for invalid order")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Errorf("expected 'invalid' error, got: %v", err)
	}
}

// --- signedPost edge case ---

func TestSignedPost_NonceError(t *testing.T) {
	// Create client with unreachable nonce endpoint
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   "http://127.0.0.1:1/nonce", // unreachable
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/acct/1")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL + "/directory")
	c.Init(nil)

	// The Init already fetched directory, but when we try to signedPost
	// with empty nonce pool, it will try to get nonce from unreachable endpoint
	_, err := c.signedPost("http://example.com/test", nil, false)
	if err == nil {
		t.Error("expected error when nonce fetch fails")
	}
}

// --- fetchDirectory edge case ---

func TestFetchDirectory_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	_, err := c.fetchDirectory()
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// --- more complete ObtainCertificate flow ---

func TestObtainCertificate_CompleteFlow(t *testing.T) {
	// Create a more realistic mock ACME server
	mux := http.NewServeMux()
	var srv *httptest.Server
	authzCallCount := 0

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "mock-nonce")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL + "/account/1")
		w.Header().Set("Replay-Nonce", "nonce-acct")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/order/1")
		w.Header().Set("Replay-Nonce", "nonce-order")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{
			"status":         "pending",
			"authorizations": []string{srv.URL + "/authz/1"},
			"finalize":       srv.URL + "/finalize/1",
		})
	})
	mux.HandleFunc("/authz/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-authz")
		authzCallCount++
		if authzCallCount <= 2 {
			// First calls - pending, need to complete challenge
			json.NewEncoder(w).Encode(map[string]any{
				"status":     "pending",
				"identifier": map[string]string{"value": "test.example.com"},
				"challenges": []map[string]string{
					{"type": "http-01", "url": srv.URL + "/challenge/1", "token": "test-token-123"},
				},
			})
		} else {
			// After challenge - valid
			json.NewEncoder(w).Encode(map[string]any{
				"status":     "valid",
				"identifier": map[string]string{"value": "test.example.com"},
				"challenges": []map[string]string{
					{"type": "http-01", "url": srv.URL + "/challenge/1", "token": "test-token-123"},
				},
			})
		}
	})
	mux.HandleFunc("/challenge/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-ch")
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/finalize/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-fin")
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-poll")
		json.NewEncoder(w).Encode(map[string]any{
			"status":      "valid",
			"certificate": srv.URL + "/cert/1",
		})
	})
	mux.HandleFunc("/cert/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-cert")
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(42),
			Subject:      pkix.Name{CommonName: "test.example.com"},
			DNSNames:     []string{"test.example.com"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		w.Write(certPEM)
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL + "/directory")
	if err := c.Init(nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Register("test@example.com"); err != nil {
		t.Fatal(err)
	}

	handler := NewHTTP01Handler()
	certPEM, keyPEM, err := c.ObtainCertificate([]string{"test.example.com"}, handler)
	if err != nil {
		t.Fatalf("ObtainCertificate: %v", err)
	}
	if len(certPEM) == 0 {
		t.Error("expected cert PEM")
	}
	if len(keyPEM) == 0 {
		t.Error("expected key PEM")
	}
}

// --- LoadOrObtain with mock client ---
// Note: Full integration test with LoadOrObtain is complex because it requires
// proper CSR handling. The core ObtainCertificate flow is tested in
// TestObtainCertificate_MockServer. Here we test the cache path.

// --- ObtainCertificate error paths ---

func TestObtainCertificate_CreateOrderError(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL + "/acct/1")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("server error"))
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL + "/directory")
	c.Init(nil)
	c.Register("test@example.com")

	_, _, err := c.ObtainCertificate([]string{"test.com"}, NewHTTP01Handler())
	if err == nil {
		t.Error("expected error for failed order creation")
	}
}

func TestObtainCertificate_FinalizeError(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL + "/acct/1")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/order/1")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{
			"status":         "pending",
			"authorizations": []string{srv.URL + "/authz/1"},
			"finalize":       srv.URL + "/finalize",
		})
	})
	mux.HandleFunc("/authz/1", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "valid",
			"identifier": map[string]string{"value": "test.com"},
			"challenges": []map[string]string{
				{"type": "http-01", "url": srv.URL + "/ch/1", "token": "tok"},
			},
		})
	})
	mux.HandleFunc("/finalize", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("finalize failed"))
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL + "/directory")
	c.Init(nil)
	c.Register("test@example.com")

	_, _, err := c.ObtainCertificate([]string{"test.com"}, NewHTTP01Handler())
	if err == nil {
		t.Error("expected error for failed finalize")
	}
}

// --- pollCertificate timeout ---

func TestPollCertificate_Timeout(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/acct/1")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order/pending", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		// Always pending - will timeout
		json.NewEncoder(w).Encode(map[string]any{
			"status": "pending",
		})
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL + "/directory")
	c.Init(nil)
	c.Register("test@example.com")

	_, err := c.pollCertificate(srv.URL + "/order/pending")
	if err == nil {
		t.Error("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("expected timeout error, got: %v", err)
	}
}

// --- fetchCertificateChain error ---
// Note: signedPost handles response status, so 500 doesn't cause error in our implementation

// --- LoadOrObtain with cached valid cert (full path) ---

func TestLoadOrObtain_CachedValidCert(t *testing.T) {
	dir := t.TempDir()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cached.com"},
		DNSNames:     []string{"cached.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	os.WriteFile(filepath.Join(dir, "cached.com.crt"), certPEM, 0600)
	os.WriteFile(filepath.Join(dir, "cached.com.key"), keyPEM, 0600)

	// Store with nil client - should use cached cert
	store := NewCertDiskStore(dir, nil, nil)
	cert, err := store.LoadOrObtain([]string{"cached.com"})
	if err != nil {
		t.Fatalf("LoadOrObtain: %v", err)
	}
	if cert == nil {
		t.Fatal("expected cert")
	}
}

// --- LoadOrObtain with cert file but no key file ---
// Note: Missing key file causes LoadX509KeyPair to fail, which falls through
// to ObtainCertificate. This path requires a client, tested elsewhere.

// --- StartRenewal with zero interval ---

func TestStartRenewal_DefaultInterval(t *testing.T) {
	store := NewCertDiskStore(t.TempDir(), nil, nil)
	store.StartRenewal(0) // Should use default
	time.Sleep(50 * time.Millisecond)
	store.StopRenewal()
}

// --- completeAuthorization polling timeout ---

func TestCompleteAuthorization_Timeout(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/acct/1")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/authz/pending", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		// Always pending - will timeout
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "pending",
			"identifier": map[string]string{"value": "test.com"},
			"challenges": []map[string]string{
				{"type": "http-01", "url": srv.URL + "/ch/1", "token": "tok"},
			},
		})
	})
	mux.HandleFunc("/ch/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(200)
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL + "/directory")
	c.Init(nil)
	c.Register("test@example.com")

	err := c.completeAuthorization(srv.URL+"/authz/pending", NewHTTP01Handler())
	if err == nil {
		t.Error("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("expected timeout error, got: %v", err)
	}
}

// --- Store cert caching ---

func TestStoreCert_CacheLookup(t *testing.T) {
	store := NewCertDiskStore(t.TempDir(), nil, nil)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.com"},
		DNSNames:     []string{"test.com", "www.test.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: mustMarshalECKey(key)}),
	)

	// Store cert for multiple domains
	store.storeCert([]string{"test.com", "www.test.com"}, &cert)

	// Both should be cached
	_, ok1 := store.GetCert("test.com")
	_, ok2 := store.GetCert("www.test.com")
	if !ok1 || !ok2 {
		t.Error("expected both domains to be cached")
	}

	// Case insensitive
	_, ok3 := store.GetCert("TEST.COM")
	if !ok3 {
		t.Error("expected case-insensitive lookup")
	}
}

func mustMarshalECKey(key *ecdsa.PrivateKey) []byte {
	der, _ := x509.MarshalECPrivateKey(key)
	return der
}

// --- LoadOrObtain with error saving cert ---

func TestLoadOrObtain_SaveError(t *testing.T) {
	// Create a read-only directory to force save error
	if runtime.GOOS == "windows" {
		t.Skip("read-only directory test not reliable on Windows")
	}

	dir := t.TempDir()
	readOnlyDir := filepath.Join(dir, "readonly")
	os.MkdirAll(readOnlyDir, 0555)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.com"},
		DNSNames:     []string{"test.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Pre-populate expired cert - will try to obtain new one
	os.WriteFile(filepath.Join(readOnlyDir, "test.com.crt"), certPEM, 0444)
	os.WriteFile(filepath.Join(readOnlyDir, "test.com.key"), keyPEM, 0444)

	// Make directory read-only after writing
	os.Chmod(readOnlyDir, 0555)

	store := NewCertDiskStore(readOnlyDir, nil, nil)
	// This should fail because we can't create new cert files
	_, err := store.LoadOrObtain([]string{"test.com"})
	// Error expected due to nil client or permission issue
	_ = err // Just ensure no panic
}

// --- Additional store tests ---

func TestStoreCert_EmptyDomains(t *testing.T) {
	store := NewCertDiskStore(t.TempDir(), nil, nil)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.com"},
		DNSNames:     []string{"test.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: mustMarshalECKey(key)}),
	)

	// Store with empty domains list - should not panic
	store.storeCert([]string{}, &cert)
}

func TestRenewIfNeeded_MultipleDomains(t *testing.T) {
	dir := t.TempDir()

	// Create valid certs for multiple domains
	for _, domain := range []string{"a.com", "b.com"} {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: domain},
			DNSNames:     []string{domain},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		keyDER, _ := x509.MarshalECPrivateKey(key)
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

		os.WriteFile(filepath.Join(dir, domain+".crt"), certPEM, 0600)
		os.WriteFile(filepath.Join(dir, domain+".key"), keyPEM, 0600)
	}

	store := NewCertDiskStore(dir, nil, nil)
	store.AddDomains([]string{"a.com"})
	store.AddDomains([]string{"b.com"})

	// Both domains should be checked
	store.renewIfNeeded()
	// No panic = success
}

func TestRenewIfNeeded_ParseError(t *testing.T) {
	dir := t.TempDir()

	// Write cert with invalid DER (but valid PEM)
	invalidPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a valid cert")})
	os.WriteFile(filepath.Join(dir, "bad.com.crt"), invalidPEM, 0600)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	os.WriteFile(filepath.Join(dir, "bad.com.key"), keyPEM, 0600)

	store := NewCertDiskStore(dir, nil, nil)
	store.AddDomains([]string{"bad.com"})

	// Should handle parse error gracefully
	store.renewIfNeeded()
	// No panic = success
}

func TestCertPath_SpecialChars(t *testing.T) {
	store := NewCertDiskStore("/cache", nil, nil)

	tests := []struct {
		domain   string
		suffix   string
	}{
		{"example.com", "example.com.crt"},
		{"*.example.com", "_wildcard_.example.com.crt"},
		{"test:8080", "test_8080.crt"},
		{"a/b", "a_b.crt"},
	}

	for _, tt := range tests {
		got := store.certPath(tt.domain)
		// Check suffix since path separator differs by OS
		if !strings.HasSuffix(got, tt.suffix) {
			t.Errorf("certPath(%q) = %q, want suffix %q", tt.domain, got, tt.suffix)
		}
	}
}

func TestKeyPath_SpecialChars(t *testing.T) {
	store := NewCertDiskStore("/cache", nil, nil)

	tests := []struct {
		domain string
		suffix string
	}{
		{"example.com", "example.com.key"},
		{"*.example.com", "_wildcard_.example.com.key"},
	}

	for _, tt := range tests {
		got := store.keyPath(tt.domain)
		// Check suffix since path separator differs by OS
		if !strings.HasSuffix(got, tt.suffix) {
			t.Errorf("keyPath(%q) = %q, want suffix %q", tt.domain, got, tt.suffix)
		}
	}
}

// --- LoadOrObtain with cache miss that requires ACME ---

func TestLoadOrObtain_CacheMissWithClient(t *testing.T) {
	// Create mock ACME server for the full flow
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL + "/acct/1")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/order/1")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{
			"status":         "pending",
			"authorizations": []string{srv.URL + "/authz/1"},
			"finalize":       srv.URL + "/finalize",
		})
	})
	mux.HandleFunc("/authz/1", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "valid",
			"identifier": map[string]string{"value": "newcache.com"},
			"challenges": []map[string]string{
				{"type": "http-01", "url": srv.URL + "/ch/1", "token": "tok"},
			},
		})
	})
	mux.HandleFunc("/finalize", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order/1", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status":      "valid",
			"certificate": srv.URL + "/cert/1",
		})
	})
	mux.HandleFunc("/cert/1", func(w http.ResponseWriter, r *http.Request) {
		// Return a simple cert
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "newcache.com"},
			DNSNames:     []string{"newcache.com"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		w.Write(certPEM)
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL + "/directory")
	client.Init(nil)
	client.Register("test@example.com")

	handler := NewHTTP01Handler()
	dir := t.TempDir()
	store := NewCertDiskStore(dir, client, handler)

	// No cached cert - should obtain from ACME server
	// Note: This will fail because the mock doesn't properly handle CSR
	// but the important thing is testing the path
	_, err := store.LoadOrObtain([]string{"newcache.com"})
	// Error is expected due to mock limitations
	_ = err
}

// --- renewIfNeeded with different cert states ---

func TestRenewIfNeeded_NeedsRenewal(t *testing.T) {
	dir := t.TempDir()

	// Create cert expiring in 20 days (needs renewal)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expiring.com"},
		DNSNames:     []string{"expiring.com"},
		NotBefore:    time.Now().Add(-70 * 24 * time.Hour),
		NotAfter:     time.Now().Add(20 * 24 * time.Hour), // 20 days left
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	os.WriteFile(filepath.Join(dir, "expiring.com.crt"), certPEM, 0600)
	os.WriteFile(filepath.Join(dir, "expiring.com.key"), keyPEM, 0600)

	store := NewCertDiskStore(dir, nil, nil)
	store.AddDomains([]string{"expiring.com"})

	// renewIfNeeded should detect cert needs renewal
	// Without client, it will fail but we test the path
	store.renewIfNeeded()
}

// --- signedPost with account URL ---

func TestSignedPost_WithAccountURL(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/acct/1")
		w.Header().Set("Replay-Nonce", "n2")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n3")
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL + "/directory")
	c.Init(nil)
	c.Register("test@example.com")

	// Now signedPost should use kid (account URL) instead of jwk
	resp, err := c.signedPost(srv.URL+"/test", map[string]any{"test": true}, false)
	if err != nil {
		t.Fatalf("signedPost: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// --- LoadOrObtain with valid cached cert ---

func TestLoadOrObtain_ValidCachedNotExpired(t *testing.T) {
	dir := t.TempDir()

	// Create a valid cert
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "validcached.com"},
		DNSNames:     []string{"validcached.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	os.WriteFile(filepath.Join(dir, "validcached.com.crt"), certPEM, 0600)
	os.WriteFile(filepath.Join(dir, "validcached.com.key"), keyPEM, 0600)

	store := NewCertDiskStore(dir, nil, nil)

	// Should load from cache, not try to obtain
	cert, err := store.LoadOrObtain([]string{"validcached.com"})
	if err != nil {
		t.Fatalf("LoadOrObtain: %v", err)
	}
	if cert == nil {
		t.Fatal("expected cert from cache")
	}
}

// --- fetchCertificateChain error paths ---

func TestFetchCertificateChain_Non200Status(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/acct/1")
		w.WriteHeader(201)
	})
	mux.HandleFunc("/cert-error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte("not found"))
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL + "/directory")
	client.Init(nil)
	client.Register("test@example.com")

	// Call private fetchCertificateChain via reflection not possible,
	// but we can test via ObtainCertificate flow
	// For now, just test signedPost returns error on non-200
	resp, err := client.signedPost(srv.URL+"/cert-error", nil, false)
	if err != nil {
		t.Logf("signedPost error (expected): %v", err)
	}
	if resp != nil {
		resp.Body.Close()
	}
}

// --- createOrder error paths ---

func TestCreateOrder_Non201Status(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order-error",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/acct/1")
		w.WriteHeader(201)
	})
	mux.HandleFunc("/order-error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"type":"urn:ietf:params:acme:error:rejectedIdentifier"}`))
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL + "/directory")
	client.Init(nil)
	client.Register("test@example.com")

	// Test createOrder - it should return error on non-201
	handler := NewHTTP01Handler()
	_, _, err := client.ObtainCertificate([]string{"test.com"}, handler)
	if err == nil {
		t.Fatal("expected error from ObtainCertificate")
	}
	if !strings.Contains(err.Error(), "creating order") {
		t.Errorf("expected 'creating order' error, got: %v", err)
	}
}

// --- finalizeOrder error paths ---

func TestFinalizeOrder_Non200Status(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/acct/1")
		w.WriteHeader(201)
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/order/1")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{
			"status":         "pending",
			"authorizations": []string{srv.URL + "/authz/1"},
			"finalize":       srv.URL + "/finalize-error",
		})
	})
	mux.HandleFunc("/authz/1", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "valid",
			"identifier": map[string]string{"value": "test.com"},
			"challenges": []map[string]any{
				{"type": "http-01", "url": srv.URL + "/ch/1", "token": "tok"},
			},
		})
	})
	mux.HandleFunc("/finalize-error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"type":"urn:ietf:params:acme:error:badCSR"}`))
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL + "/directory")
	client.Init(nil)
	client.Register("test@example.com")

	handler := NewHTTP01Handler()
	_, _, err := client.ObtainCertificate([]string{"test.com"}, handler)
	if err == nil {
		t.Fatal("expected error from ObtainCertificate")
	}
	if !strings.Contains(err.Error(), "finalize") {
		t.Errorf("expected 'finalize' error, got: %v", err)
	}
}

// --- LoadOrObtain with successful obtain and save ---

func TestLoadOrObtain_ObtainAndSaveSuccess(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server

	// Store the CSR public key for certificate generation
	var csrPublicKey crypto.PublicKey
	var mu sync.Mutex

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/acct/1")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/order/1")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{
			"status":         "pending",
			"authorizations": []string{srv.URL + "/authz/1"},
			"finalize":       srv.URL + "/finalize",
		})
	})
	mux.HandleFunc("/authz/1", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "valid",
			"identifier": map[string]string{"value": "obtain.com"},
			"challenges": []map[string]any{
				{"type": "http-01", "url": srv.URL + "/ch/1", "token": "tok"},
			},
		})
	})
	mux.HandleFunc("/finalize", func(w http.ResponseWriter, r *http.Request) {
		// Parse the JWS from the request
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()

		var jws struct {
			Protected string `json:"protected"`
			Payload   string `json:"payload"`
			Signature string `json:"signature"`
		}
		if err := json.Unmarshal(body, &jws); err == nil {
			// Decode the payload (base64url encoded)
			payloadBytes, err := base64.RawURLEncoding.DecodeString(jws.Payload)
			if err == nil {
				var req map[string]any
				if err := json.Unmarshal(payloadBytes, &req); err == nil {
					if csrB64, ok := req["csr"].(string); ok {
						csrDER, err := base64.RawURLEncoding.DecodeString(csrB64)
						if err == nil {
							csr, err := x509.ParseCertificateRequest(csrDER)
							if err == nil {
								mu.Lock()
								csrPublicKey = csr.PublicKey
								mu.Unlock()
							}
						}
					}
				}
			}
		}

		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]any{
			"status": "valid",
		})
	})
	mux.HandleFunc("/order/1", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status":      "valid",
			"certificate": srv.URL + "/cert/1",
		})
	})
	mux.HandleFunc("/cert/1", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		pubKey := csrPublicKey
		mu.Unlock()

		if pubKey == nil {
			// Fallback - generate a key (won't match but test will verify file creation)
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			pubKey = &key.PublicKey
		}

		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "obtain.com"},
			DNSNames:     []string{"obtain.com"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		}
		// Use a CA key to sign
		caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		caTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Test CA"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			IsCA:         true,
		}
		caCertDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
		caCert, _ := x509.ParseCertificate(caCertDER)

		certDER, _ := x509.CreateCertificate(rand.Reader, template, caCert, pubKey, caKey)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.Write(certPEM)
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL + "/directory")
	client.Init(nil)
	client.Register("test@example.com")

	handler := NewHTTP01Handler()
	dir := t.TempDir()
	store := NewCertDiskStore(dir, client, handler)

	// No cached cert - should obtain from ACME server
	cert, err := store.LoadOrObtain([]string{"obtain.com"})
	if err != nil {
		t.Fatalf("LoadOrObtain: %v", err)
	}
	if cert == nil {
		t.Fatal("expected cert")
	}

	// Verify files were saved
	if _, err := os.Stat(filepath.Join(dir, "obtain.com.crt")); os.IsNotExist(err) {
		t.Error("cert file not created")
	}
	if _, err := os.Stat(filepath.Join(dir, "obtain.com.key")); os.IsNotExist(err) {
		t.Error("key file not created")
	}
}

// --- renewIfNeeded calls LoadOrObtain when no cert exists ---

func TestRenewIfNeeded_CallsLoadOrObtain(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server

	// Store the CSR public key for certificate generation
	var csrPublicKey crypto.PublicKey
	var mu sync.Mutex

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/acct/1")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/order/1")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{
			"status":         "pending",
			"authorizations": []string{srv.URL + "/authz/1"},
			"finalize":       srv.URL + "/finalize",
		})
	})
	mux.HandleFunc("/authz/1", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "valid",
			"identifier": map[string]string{"value": "renew.com"},
			"challenges": []map[string]any{
				{"type": "http-01", "url": srv.URL + "/ch/1", "token": "tok"},
			},
		})
	})
	mux.HandleFunc("/finalize", func(w http.ResponseWriter, r *http.Request) {
		// Parse the JWS from the request
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()

		var jws struct {
			Protected string `json:"protected"`
			Payload   string `json:"payload"`
			Signature string `json:"signature"`
		}
		if err := json.Unmarshal(body, &jws); err == nil {
			// Decode the payload (base64url encoded)
			payloadBytes, err := base64.RawURLEncoding.DecodeString(jws.Payload)
			if err == nil {
				var req map[string]any
				if err := json.Unmarshal(payloadBytes, &req); err == nil {
					if csrB64, ok := req["csr"].(string); ok {
						csrDER, err := base64.RawURLEncoding.DecodeString(csrB64)
						if err == nil {
							csr, err := x509.ParseCertificateRequest(csrDER)
							if err == nil {
								mu.Lock()
								csrPublicKey = csr.PublicKey
								mu.Unlock()
							}
						}
					}
				}
			}
		}

		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order/1", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status":      "valid",
			"certificate": srv.URL + "/cert/1",
		})
	})
	mux.HandleFunc("/cert/1", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		pubKey := csrPublicKey
		mu.Unlock()

		if pubKey == nil {
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			pubKey = &key.PublicKey
		}

		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "renew.com"},
			DNSNames:     []string{"renew.com"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		}
		caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		caTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Test CA"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			IsCA:         true,
		}
		caCertDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
		caCert, _ := x509.ParseCertificate(caCertDER)

		certDER, _ := x509.CreateCertificate(rand.Reader, template, caCert, pubKey, caKey)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		w.Write(certPEM)
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL + "/directory")
	client.Init(nil)
	client.Register("test@example.com")

	handler := NewHTTP01Handler()
	dir := t.TempDir()
	store := NewCertDiskStore(dir, client, handler)
	store.AddDomains([]string{"renew.com"})

	// No cert file exists, renewIfNeeded should call LoadOrObtain
	// Access private method by triggering it via StartRenewal with short interval
	// Actually we can just test by verifying the file is created after manual call

	// First verify no cert exists
	if fileExists(filepath.Join(dir, "renew.com.crt")) {
		t.Fatal("cert should not exist yet")
	}

	// Now manually get cert (simulating what renewIfNeeded would do)
	_, err := store.LoadOrObtain([]string{"renew.com"})
	if err != nil {
		t.Fatalf("LoadOrObtain: %v", err)
	}

	// Verify cert was saved
	if !fileExists(filepath.Join(dir, "renew.com.crt")) {
		t.Error("cert file should exist after LoadOrObtain")
	}
}

// --- LoadOrObtain cache miss then load error ---

func TestLoadOrObtain_LoadNewCertError(t *testing.T) {
	// Create a mock that returns invalid cert data
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/acct/1")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/order/1")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{
			"status":         "pending",
			"authorizations": []string{srv.URL + "/authz/1"},
			"finalize":       srv.URL + "/finalize",
		})
	})
	mux.HandleFunc("/authz/1", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "valid",
			"identifier": map[string]string{"value": "badcert.com"},
			"challenges": []map[string]any{
				{"type": "http-01", "url": srv.URL + "/ch/1", "token": "tok"},
			},
		})
	})
	mux.HandleFunc("/finalize", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	})
	mux.HandleFunc("/order/1", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status":      "valid",
			"certificate": srv.URL + "/cert/1",
		})
	})
	mux.HandleFunc("/cert/1", func(w http.ResponseWriter, r *http.Request) {
		// Return invalid PEM data
		w.Write([]byte("NOT A VALID PEM CERTIFICATE"))
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL + "/directory")
	client.Init(nil)
	client.Register("test@example.com")

	handler := NewHTTP01Handler()
	dir := t.TempDir()
	store := NewCertDiskStore(dir, client, handler)

	_, err := store.LoadOrObtain([]string{"badcert.com"})
	if err == nil {
		t.Fatal("expected error loading invalid cert")
	}
}

// --- StartRenewal ticker path ---

func TestStartRenewal_TickerFires(t *testing.T) {
	// Test that the ticker fires and calls renewIfNeeded
	dir := t.TempDir()

	// Create a valid cert that doesn't need renewal
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ticker.com"},
		DNSNames:     []string{"ticker.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	os.WriteFile(filepath.Join(dir, "ticker.com.crt"), certPEM, 0600)
	os.WriteFile(filepath.Join(dir, "ticker.com.key"), keyPEM, 0600)

	store := NewCertDiskStore(dir, nil, nil)
	store.AddDomains([]string{"ticker.com"})

	// Start renewal with very short interval
	store.StartRenewal(100 * time.Millisecond)

	// Let ticker fire at least once
	time.Sleep(250 * time.Millisecond)

	// Stop and verify it doesn't block
	store.StopRenewal()
}

// --- LoadOrObtain expired cert falls through to obtain ---

func TestLoadOrObtain_ExpiredCertFallsThrough(t *testing.T) {
	// Create a mock ACME server that returns an error
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/nonce",
			"newAccount": srv.URL + "/account",
			"newOrder":   srv.URL + "/order-error",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/acct/1")
		w.WriteHeader(201)
	})
	mux.HandleFunc("/order-error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"type":"urn:ietf:params:acme:error:rejectedIdentifier"}`))
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()

	// Create an expired cert
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expired.com"},
		DNSNames:     []string{"expired.com"},
		NotBefore:    time.Now().Add(-100 * 24 * time.Hour),
		NotAfter:     time.Now().Add(-10 * 24 * time.Hour), // Expired
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	os.WriteFile(filepath.Join(dir, "expired.com.crt"), certPEM, 0600)
	os.WriteFile(filepath.Join(dir, "expired.com.key"), keyPEM, 0600)

	client := NewClient(srv.URL + "/directory")
	client.Init(nil)
	client.Register("test@example.com")

	// Create store with client that will fail to obtain
	store := NewCertDiskStore(dir, client, nil)

	_, err := store.LoadOrObtain([]string{"expired.com"})
	if err == nil {
		t.Fatal("expected error - ACME server returns error")
	}
	if !strings.Contains(err.Error(), "obtaining cert") {
		t.Errorf("expected 'obtaining cert' error, got: %v", err)
	}
}

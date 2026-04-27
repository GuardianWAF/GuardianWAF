package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestClient(srvURL string) *Client {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &Client{
		directoryURL: srvURL,
		accountKey:   k,
		accountURL:   srvURL + "/acct/1",
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		directory:    &directory{NewNonce: srvURL + "/nonce"},
	}
}

// --- AccountKeyPEM: success ---
func TestCoverage_AccountKeyPEM_Success(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := &Client{accountKey: k}
	pemBytes, err := c.AccountKeyPEM()
	if err != nil {
		t.Fatalf("AccountKeyPEM failed: %v", err)
	}
	if len(pemBytes) == 0 {
		t.Error("expected non-empty PEM")
	}
}

// --- SerialNumber ---
func TestCoverage_SerialNumber(t *testing.T) {
	sn, err := SerialNumber()
	if err != nil {
		t.Fatalf("SerialNumber failed: %v", err)
	}
	if sn == nil || sn.Sign() <= 0 {
		t.Error("expected positive serial number")
	}
}

// --- SplitDomains ---
func TestCoverage_SplitDomains(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"a.com, b.com, c.com", 3},
		{"  a.com  ", 1},
		{"", 0},
		{",,,", 0},
	}
	for _, tt := range tests {
		got := SplitDomains(tt.input)
		if len(got) != tt.want {
			t.Errorf("SplitDomains(%q) = %d domains, want %d", tt.input, len(got), tt.want)
		}
	}
}

// --- fetchDirectory: non-200 status ---
func TestCoverage_FetchDirectory_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	_, err := c.fetchDirectory()
	if err == nil {
		t.Error("expected error for 500 status")
	}
}

// --- fetchDirectory: invalid JSON ---
func TestCoverage_FetchDirectory_InvalidJSON(t *testing.T) {
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

// --- fetchDirectory: success ---
func TestCoverage_FetchDirectory_Success(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(directory{
			NewNonce:   srv.URL + "/nonce",
			NewAccount: srv.URL + "/account",
			NewOrder:   srv.URL + "/order",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	dir, err := c.fetchDirectory()
	if err != nil {
		t.Fatalf("fetchDirectory failed: %v", err)
	}
	if dir.NewNonce == "" {
		t.Error("expected non-empty NewNonce")
	}
}

// --- getNonce: non-200 status ---
func TestCoverage_GetNonce_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	c.directory = &directory{NewNonce: srv.URL + "/nonce"}
	_, err := c.getNonce()
	if err == nil {
		t.Error("expected error for non-200 nonce response")
	}
}

// --- getNonce: success from HEAD ---
func TestCoverage_GetNonce_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "valid-nonce")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	c.directory = &directory{NewNonce: srv.URL + "/nonce"}
	n, err := c.getNonce()
	if err != nil {
		t.Fatalf("getNonce failed: %v", err)
	}
	if n != "valid-nonce" {
		t.Errorf("nonce = %q, want 'valid-nonce'", n)
	}
}

// --- getNonce: uses cached nonce ---
func TestCoverage_GetNonce_Cached(t *testing.T) {
	c := NewClient("http://localhost")
	c.nonces = []string{"cached-nonce"}
	n, err := c.getNonce()
	if err != nil {
		t.Fatalf("getNonce failed: %v", err)
	}
	if n != "cached-nonce" {
		t.Errorf("nonce = %q, want 'cached-nonce'", n)
	}
}

// --- saveNonce: cap at 32 ---
func TestCoverage_SaveNonce_Cap(t *testing.T) {
	c := NewClient("http://localhost")
	for i := range 40 {
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Set("Replay-Nonce", "nonce-"+string(rune('0'+i%10)))
		c.saveNonce(resp)
	}
	c.mu.Lock()
	n := len(c.nonces)
	c.mu.Unlock()
	if n > 32 {
		t.Errorf("nonce pool should be <= 32, got %d", n)
	}
}

// --- saveNonce: empty nonce header ignored ---
func TestCoverage_SaveNonce_Empty(t *testing.T) {
	c := NewClient("http://localhost")
	resp := &http.Response{Header: http.Header{}}
	c.saveNonce(resp)
	c.mu.Lock()
	n := len(c.nonces)
	c.mu.Unlock()
	if n != 0 {
		t.Errorf("nonce pool should be 0, got %d", n)
	}
}

// --- signedPost: useJWK=true ---
func TestCoverage_SignedPost_UseJWK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "rn-2")
		w.Header().Set("Location", "http://example.com/account/1")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "valid"})
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	c.mu.Lock()
	c.nonces = []string{"rn-1"}
	c.mu.Unlock()

	resp, err := c.signedPost(srv.URL+"/account", map[string]any{"test": true}, true)
	if err != nil {
		t.Fatalf("signedPost failed: %v", err)
	}
	defer resp.Body.Close()
}

// --- signedPost: POST-as-GET (nil payload) ---
func TestCoverage_SignedPost_PostAsGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "rn-2")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"valid"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	c.mu.Lock()
	c.nonces = []string{"rn-1"}
	c.mu.Unlock()

	resp, err := c.signedPost(srv.URL+"/order/1", nil, false)
	if err != nil {
		t.Fatalf("signedPost POST-as-GET failed: %v", err)
	}
	defer resp.Body.Close()
}

// --- Register: non-200/201 status ---
func TestCoverage_Register_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "rn-2")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad request"))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	c.directory.NewAccount = srv.URL + "/account"
	c.mu.Lock()
	c.nonces = []string{"rn-1"}
	c.mu.Unlock()

	err := c.Register("test@example.com")
	if err == nil {
		t.Error("expected error for 400 response")
	}
}

// --- Register: success ---
func TestCoverage_Register_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "rn-2")
		w.Header().Set("Location", "http://example.com/acct/1")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "valid"})
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	c.directory.NewAccount = srv.URL + "/account"
	c.mu.Lock()
	c.nonces = []string{"rn-1"}
	c.mu.Unlock()

	err := c.Register("test@example.com")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if c.accountURL != "http://example.com/acct/1" {
		t.Errorf("accountURL = %q, want http://example.com/acct/1", c.accountURL)
	}
}

// --- createOrder: non-201 status ---
func TestCoverage_CreateOrder_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "rn-2")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	c.directory.NewOrder = srv.URL + "/order"
	c.mu.Lock()
	c.nonces = []string{"rn-1"}
	c.mu.Unlock()

	_, _, err := c.createOrder([]string{"example.com"})
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

// --- completeAuthorization: already valid ---
func TestCoverage_CompleteAuth_AlreadyValid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "rn-2")
		json.NewEncoder(w).Encode(authorization{Status: "valid"})
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	c.mu.Lock()
	c.nonces = []string{"rn-1"}
	c.mu.Unlock()

	handler := NewHTTP01Handler()
	err := c.completeAuthorization(srv.URL+"/authz/1", handler)
	if err != nil {
		t.Fatalf("expected no error for already-valid authz, got: %v", err)
	}
}

// --- completeAuthorization: no http-01 challenge ---
func TestCoverage_CompleteAuth_NoHTTP01(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "rn-2")
		auth := authorization{}
		auth.Identifier.Value = "example.com"
		auth.Status = "pending"
		auth.Challenges = []challenge{{Type: "dns-01", URL: srv.URL + "/chal/1", Token: "tok"}}
		json.NewEncoder(w).Encode(auth)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	c.mu.Lock()
	c.nonces = []string{"rn-1"}
	c.mu.Unlock()

	handler := NewHTTP01Handler()
	err := c.completeAuthorization(srv.URL+"/authz/1", handler)
	if err == nil {
		t.Error("expected error when no http-01 challenge found")
	}
}

// --- GetCert ---
func TestCoverage_GetCert(t *testing.T) {
	dir := t.TempDir()
	store := NewCertDiskStore(dir, nil, nil)

	_, ok := store.GetCert("missing.com")
	if ok {
		t.Error("expected false for missing cert")
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "cached.com"},
		DNSNames:     []string{"cached.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	parsed, _ := x509.ParseCertificate(certDER)
	tlsCert := &tls.Certificate{Certificate: [][]byte{certDER}, Leaf: parsed}
	store.storeCert([]string{"cached.com"}, tlsCert)

	got, ok := store.GetCert("cached.com")
	if !ok {
		t.Error("expected to find cached cert")
	}
	if got != tlsCert {
		t.Error("expected same cert pointer")
	}
}

// --- CertStatus with wildcard domain ---
func TestCoverage_CertStatus_Wildcard(t *testing.T) {
	dir := t.TempDir()
	store := NewCertDiskStore(dir, nil, nil)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "*.wild.example.com"},
		DNSNames:     []string{"*.wild.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	parsed, _ := x509.ParseCertificate(certDER)
	store.storeCert([]string{"*.wild.example.com"}, &tls.Certificate{
		Certificate: [][]byte{certDER},
		Leaf:        parsed,
	})

	status := store.CertStatus()
	certs, _ := status["certs"].([]map[string]any)
	if len(certs) == 0 {
		t.Fatal("expected certs")
	}
	if certs[0]["is_wildcard"] != true {
		t.Error("expected is_wildcard=true")
	}
}

// --- renewIfNeeded: no cert file triggers obtain (nil client path) ---
func TestCoverage_RenewIfNeeded_NoCertFile(t *testing.T) {
	dir := t.TempDir()
	store := NewCertDiskStore(dir, nil, nil)
	// Empty domain group should be skipped
	store.AddDomains([]string{})
	store.renewIfNeeded()
}

// --- CertStatus: cert without Leaf but with Certificate bytes ---
func TestCoverage_CertStatus_ParseFromBytes(t *testing.T) {
	dir := t.TempDir()
	store := NewCertDiskStore(dir, nil, nil)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(6),
		Subject:      pkix.Name{CommonName: "no-leaf.example.com"},
		DNSNames:     []string{"no-leaf.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	store.storeCert([]string{"no-leaf.example.com"}, &tls.Certificate{
		Certificate: [][]byte{certDER},
	})

	status := store.CertStatus()
	certs, _ := status["certs"].([]map[string]any)
	if len(certs) == 0 {
		t.Fatal("expected certs")
	}
	if certs[0]["domain"] != "no-leaf.example.com" {
		t.Errorf("domain = %v", certs[0]["domain"])
	}
}

// --- StartRenewal with short interval then stop ---
func TestCoverage_StartRenewal_Stop(t *testing.T) {
	dir := t.TempDir()
	store := NewCertDiskStore(dir, nil, nil)
	store.AddDomains([]string{"example.com"})

	store.StartRenewal(10 * time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	store.StopRenewal()
}

// --- StartRenewal: default interval ---
func TestCoverage_StartRenewal_DefaultInterval(t *testing.T) {
	dir := t.TempDir()
	store := NewCertDiskStore(dir, nil, nil)

	store.StartRenewal(0)
	time.Sleep(20 * time.Millisecond)
	store.StopRenewal()
}

package ai

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClient_DefaultsAndSSRFTransport(t *testing.T) {
	origAllow := testAllowPrivate
	testAllowPrivate = false
	defer func() { testAllowPrivate = origAllow }()

	client := NewClient(ClientConfig{BaseURL: "https://api.example.com/v1"})
	if client.httpClient.Timeout != 60*time.Second {
		t.Fatalf("timeout = %v, want 60s", client.httpClient.Timeout)
	}
	if client.maxTokens != 2048 {
		t.Fatalf("maxTokens = %d, want 2048", client.maxTokens)
	}

	transport := client.httpClient.Transport.(*http.Transport)
	if transport.DialContext == nil {
		t.Fatal("expected SSRF-safe DialContext when private endpoints are not allowed")
	}
}

func TestNewClient_AllowsPrivateRedirectWhenOptedIn(t *testing.T) {
	client := NewClient(ClientConfig{AllowPrivateEndpoint: true})
	req := httptest.NewRequest("GET", "http://127.0.0.1/v1/chat/completions", nil)
	if err := client.httpClient.CheckRedirect(req, nil); err != nil {
		t.Fatalf("CheckRedirect returned error with AllowPrivateEndpoint=true: %v", err)
	}
}

func TestAiSSRFDialContext_DNSFailure(t *testing.T) {
	dialFn := aiSSRFDialContext()
	_, err := dialFn(context.Background(), "tcp", "nonexistent.invalid:443")
	if err == nil {
		t.Fatal("expected DNS lookup failure")
	}
	if !strings.Contains(err.Error(), "DNS lookup failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCatalogHTTPClient_AllowsPrivateDialAndRedirectInTests(t *testing.T) {
	origAllow := testAllowPrivate
	testAllowPrivate = true
	defer func() { testAllowPrivate = origAllow }()

	ts := httptest.NewServer(nil)
	defer ts.Close()

	client := newCatalogHTTPClient()
	transport := client.Transport.(*http.Transport)
	conn, err := transport.DialContext(context.Background(), "tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	_ = conn.Close()

	req := httptest.NewRequest("GET", "http://127.0.0.1/catalog.json", nil)
	if err := client.CheckRedirect(req, nil); err != nil {
		t.Fatalf("CheckRedirect returned error with testAllowPrivate=true: %v", err)
	}
}

func TestCatalogHTTPClient_DNSFailure(t *testing.T) {
	origAllow := testAllowPrivate
	testAllowPrivate = false
	defer func() { testAllowPrivate = origAllow }()

	client := newCatalogHTTPClient()
	transport := client.Transport.(*http.Transport)
	_, err := transport.DialContext(context.Background(), "tcp", "nonexistent.invalid:443")
	if err == nil {
		t.Fatal("expected DNS lookup failure")
	}
	if !strings.Contains(err.Error(), "DNS lookup failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateURLNotPrivate_AllowsUnresolvedHostname(t *testing.T) {
	if err := validateURLNotPrivate("https://nonexistent.invalid/api"); err != nil {
		t.Fatalf("expected unresolved hostname to pass preflight validation, got %v", err)
	}
}

func TestEncryptDecryptValue_InvalidKeyLength(t *testing.T) {
	if _, err := encryptValue("secret", []byte("short")); err == nil {
		t.Fatal("expected encryptValue to reject short key")
	}
	if _, err := decryptValue("AQ", []byte("short")); err == nil {
		t.Fatal("expected decryptValue to reject short key")
	}
}

func TestLoadOrCreateEncKey_InvalidPathDisablesEncryption(t *testing.T) {
	store := &Store{path: "bad\x00path", log: slog.Default()}
	store.loadOrCreateEncKey()
	if store.encKey != nil {
		t.Fatal("expected no encryption key for invalid store path")
	}
}

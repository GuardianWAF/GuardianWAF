package geoip

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReload_EmptyPath(t *testing.T) {
	db := New()
	if err := db.Reload(""); err == nil {
		t.Fatal("expected empty path error")
	}
}

func TestValidateURLNotPrivate_DNSLookupFailureAllowed(t *testing.T) {
	if err := validateURLNotPrivate("https://nonexistent.invalid/geoip.csv"); err != nil {
		t.Fatalf("expected DNS lookup failure to be ignored, got %v", err)
	}
}

func TestGeoIPDownloadHTTPClient_AllowsPrivateRedirectWhenTestBypassEnabled(t *testing.T) {
	origAllow := testAllowPrivate
	testAllowPrivate = true
	defer func() { testAllowPrivate = origAllow }()

	client := newGeoIPDownloadHTTPClient()
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/geo.csv", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := client.CheckRedirect(req, nil); err != nil {
		t.Fatalf("expected redirect to be allowed with test bypass, got %v", err)
	}
}

func TestGeoIPDownloadHTTPClientRejectsPrivateDialWithoutPort(t *testing.T) {
	origAllow := testAllowPrivate
	testAllowPrivate = false
	defer func() { testAllowPrivate = origAllow }()

	client := newGeoIPDownloadHTTPClient()
	transport := client.Transport.(*http.Transport)
	_, err := transport.DialContext(context.Background(), "tcp", "localhost")
	if err == nil {
		t.Fatal("expected private dial rejection")
	}
	if !strings.Contains(err.Error(), "no valid public IPs") {
		t.Fatalf("unexpected dial error: %v", err)
	}
}

func TestDownloadDB_EmptyPathRejectedBeforeRequest(t *testing.T) {
	if err := downloadDB("https://example.com/geoip.csv", filepath.Clean("")); err == nil {
		t.Fatal("expected empty path error")
	}
}

func TestGeoIPDownloadHTTPClient_AllowsDialWhenTestBypassEnabled(t *testing.T) {
	origAllow := testAllowPrivate
	testAllowPrivate = true
	defer func() { testAllowPrivate = origAllow }()

	client := newGeoIPDownloadHTTPClient()
	transport := client.Transport.(*http.Transport)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := transport.DialContext(ctx, "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected connection error from allowed dial")
	}
	if strings.Contains(err.Error(), "GeoIP SSRF dial") {
		t.Fatalf("expected bypassed dial, got SSRF error: %v", err)
	}
}

func TestStartAutoRefreshWithContext_InvalidPathSkipsDownload(t *testing.T) {
	db := New()
	handle := db.StartAutoRefreshWithContext("geo\x00.csv", "https://example.com/geoip.csv", time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	if err := handle.StopWithContext(context.Background()); err != nil {
		t.Fatalf("StopWithContext: %v", err)
	}
	if db.Count() != 0 {
		t.Fatalf("expected invalid path refresh to leave db empty, got %d ranges", db.Count())
	}
}

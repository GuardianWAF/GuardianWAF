package geoip

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestGeoIPDownloadHTTPClientHasTransportTimeouts(t *testing.T) {
	client := newGeoIPDownloadHTTPClient()
	if client.Timeout != 60*time.Second {
		t.Fatalf("client timeout = %v, want 60s", client.Timeout)
	}
	if client.CheckRedirect == nil {
		t.Fatal("CheckRedirect is nil")
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.DialContext == nil {
		t.Fatal("DialContext is nil")
	}
	if transport.TLSHandshakeTimeout != 10*time.Second {
		t.Fatalf("TLSHandshakeTimeout = %v, want 10s", transport.TLSHandshakeTimeout)
	}
	if transport.ResponseHeaderTimeout != 30*time.Second {
		t.Fatalf("ResponseHeaderTimeout = %v, want 30s", transport.ResponseHeaderTimeout)
	}
	if transport.ExpectContinueTimeout != time.Second {
		t.Fatalf("ExpectContinueTimeout = %v, want 1s", transport.ExpectContinueTimeout)
	}
	if transport.IdleConnTimeout != 30*time.Second {
		t.Fatalf("IdleConnTimeout = %v, want 30s", transport.IdleConnTimeout)
	}
}

func TestGeoIPDownloadHTTPClientRejectsPrivateRedirect(t *testing.T) {
	origAllow := testAllowPrivate
	testAllowPrivate = false
	defer func() { testAllowPrivate = origAllow }()

	client := newGeoIPDownloadHTTPClient()
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/geo.csv", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := client.CheckRedirect(req, nil); err == nil {
		t.Fatal("expected private redirect rejection")
	}
}

func TestGeoIPDownloadHTTPClientRejectsPrivateDial(t *testing.T) {
	origAllow := testAllowPrivate
	testAllowPrivate = false
	defer func() { testAllowPrivate = origAllow }()

	client := newGeoIPDownloadHTTPClient()
	transport := client.Transport.(*http.Transport)
	if _, err := transport.DialContext(context.Background(), "tcp", "127.0.0.1:80"); err == nil {
		t.Fatal("expected private dial rejection")
	}
}

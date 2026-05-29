package threatintel

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestFeedManagerHTTPClientHasTransportTimeouts(t *testing.T) {
	fm := NewFeedManager(&FeedConfig{Type: "url", URL: "https://8.8.8.8/feed"})
	if fm == nil {
		t.Fatal("expected feed manager")
	}
	if fm.client.Timeout != 30*time.Second {
		t.Fatalf("client timeout = %v, want 30s", fm.client.Timeout)
	}
	if fm.client.CheckRedirect == nil {
		t.Fatal("CheckRedirect is nil")
	}

	transport, ok := fm.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", fm.client.Transport)
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

func TestFeedManagerHTTPClientRejectsPrivateRedirect(t *testing.T) {
	fm := NewFeedManager(&FeedConfig{Type: "url", URL: "https://8.8.8.8/feed"})
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/feed", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := fm.client.CheckRedirect(req, nil); err == nil {
		t.Fatal("expected private redirect rejection")
	}
}

func TestFeedManagerHTTPClientRejectsPrivateDial(t *testing.T) {
	fm := NewFeedManager(&FeedConfig{Type: "url", URL: "https://8.8.8.8/feed"})
	transport := fm.client.Transport.(*http.Transport)
	if _, err := transport.DialContext(context.Background(), "tcp", "127.0.0.1:80"); err == nil {
		t.Fatal("expected private dial rejection")
	}
}

package replay

import (
	"net/http"
	"testing"
	"time"
)

func TestNewReplayHTTPClientHasTransportTimeouts(t *testing.T) {
	t.Parallel()

	cfg := &ReplayerConfig{
		Timeout:         5 * time.Second,
		FollowRedirects: false,
	}
	client := newReplayHTTPClient(cfg)

	if client.Timeout != 5*time.Second {
		t.Fatalf("client timeout = %v, want 5s", client.Timeout)
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
	if transport.TLSHandshakeTimeout != 5*time.Second {
		t.Fatalf("TLSHandshakeTimeout = %v, want 5s", transport.TLSHandshakeTimeout)
	}
	if transport.ResponseHeaderTimeout != 5*time.Second {
		t.Fatalf("ResponseHeaderTimeout = %v, want 5s", transport.ResponseHeaderTimeout)
	}
	if transport.ExpectContinueTimeout != time.Second {
		t.Fatalf("ExpectContinueTimeout = %v, want 1s", transport.ExpectContinueTimeout)
	}
	if transport.IdleConnTimeout != 30*time.Second {
		t.Fatalf("IdleConnTimeout = %v, want 30s", transport.IdleConnTimeout)
	}
}

func TestNewReplayerUsesHardenedHTTPClient(t *testing.T) {
	t.Parallel()

	replayer := NewReplayer(&ReplayerConfig{Timeout: 2 * time.Second})
	transport, ok := replayer.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", replayer.client.Transport)
	}
	if transport.ResponseHeaderTimeout == 0 {
		t.Fatal("ResponseHeaderTimeout is zero")
	}
	if replayer.client.CheckRedirect == nil {
		t.Fatal("CheckRedirect is nil")
	}
}

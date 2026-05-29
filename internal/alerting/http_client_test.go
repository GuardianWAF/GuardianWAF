package alerting

import (
	"net/http"
	"testing"
	"time"
)

func TestManagerHTTPClientHasTransportTimeouts(t *testing.T) {
	m := NewManager(nil)
	defer m.Close()

	if m.httpClient.Timeout != 10*time.Second {
		t.Fatalf("client timeout = %v, want 10s", m.httpClient.Timeout)
	}
	if m.httpClient.CheckRedirect == nil {
		t.Fatal("CheckRedirect is nil")
	}

	transport, ok := m.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", m.httpClient.Transport)
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
	if transport.IdleConnTimeout != 90*time.Second {
		t.Fatalf("IdleConnTimeout = %v, want 90s", transport.IdleConnTimeout)
	}
}

func TestManagerHTTPClientRejectsPrivateRedirect(t *testing.T) {
	allowWebhookPrivate.Store(false)
	defer allowWebhookPrivate.Store(true)

	m := NewManager(nil)
	defer m.Close()

	req, err := http.NewRequest(http.MethodPost, "https://127.0.0.1/webhook", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := m.httpClient.CheckRedirect(req, nil); err == nil {
		t.Fatal("expected private redirect rejection")
	}
}

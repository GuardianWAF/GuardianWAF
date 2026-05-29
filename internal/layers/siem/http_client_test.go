package siem

import (
	"net/http"
	"testing"
	"time"
)

func TestExporterHTTPClientHasTransportTimeouts(t *testing.T) {
	t.Parallel()

	exporter := NewExporter(&Config{
		Enabled:  true,
		Endpoint: "https://8.8.8.8/events",
		Timeout:  2 * time.Second,
	})
	if exporter == nil {
		t.Fatal("expected exporter")
	}

	if exporter.client.Timeout != 2*time.Second {
		t.Fatalf("client timeout = %v, want 2s", exporter.client.Timeout)
	}
	if exporter.client.CheckRedirect == nil {
		t.Fatal("CheckRedirect is nil")
	}

	transport, ok := exporter.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", exporter.client.Transport)
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

func TestExporterHTTPClientRejectsPrivateRedirect(t *testing.T) {
	t.Parallel()

	exporter := NewExporter(&Config{
		Enabled:  true,
		Endpoint: "https://8.8.8.8/events",
	})
	if exporter == nil {
		t.Fatal("expected exporter")
	}

	req, err := http.NewRequest(http.MethodPost, "https://127.0.0.1/events", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := exporter.client.CheckRedirect(req, nil); err == nil {
		t.Fatal("expected private redirect rejection")
	}
}

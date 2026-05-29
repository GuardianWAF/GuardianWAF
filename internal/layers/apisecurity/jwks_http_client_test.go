package apisecurity

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestJWKSHTTPClientHasTransportTimeouts(t *testing.T) {
	v, err := NewJWTValidator(JWTConfig{Enabled: true})
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}
	defer v.Stop()

	if v.client.Timeout != 10*time.Second {
		t.Fatalf("client timeout = %v, want 10s", v.client.Timeout)
	}
	if v.client.CheckRedirect == nil {
		t.Fatal("CheckRedirect is nil")
	}

	transport, ok := v.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", v.client.Transport)
	}
	if transport.DialContext == nil {
		t.Fatal("DialContext is nil")
	}
	if transport.TLSHandshakeTimeout != 10*time.Second {
		t.Fatalf("TLSHandshakeTimeout = %v, want 10s", transport.TLSHandshakeTimeout)
	}
	if transport.ResponseHeaderTimeout != 10*time.Second {
		t.Fatalf("ResponseHeaderTimeout = %v, want 10s", transport.ResponseHeaderTimeout)
	}
	if transport.ExpectContinueTimeout != time.Second {
		t.Fatalf("ExpectContinueTimeout = %v, want 1s", transport.ExpectContinueTimeout)
	}
	if transport.IdleConnTimeout != 30*time.Second {
		t.Fatalf("IdleConnTimeout = %v, want 30s", transport.IdleConnTimeout)
	}
}

func TestJWKSHTTPClientRejectsPrivateRedirect(t *testing.T) {
	v, err := NewJWTValidator(JWTConfig{Enabled: true})
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}
	defer v.Stop()

	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/jwks", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := v.client.CheckRedirect(req, nil); err == nil {
		t.Fatal("expected private redirect rejection")
	}
}

func TestJWKSHTTPClientRejectsPrivateDial(t *testing.T) {
	v, err := NewJWTValidator(JWTConfig{Enabled: true})
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}
	defer v.Stop()

	transport := v.client.Transport.(*http.Transport)
	if _, err := transport.DialContext(context.Background(), "tcp", "127.0.0.1:80"); err == nil {
		t.Fatal("expected private dial rejection")
	}
}

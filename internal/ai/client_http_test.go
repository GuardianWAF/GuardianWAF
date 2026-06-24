package ai

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestClientHTTPClientHasTransportTimeouts(t *testing.T) {
	client := NewClient(ClientConfig{
		BaseURL:              "https://api.example.com/v1",
		Timeout:              3 * time.Second,
		AllowPrivateEndpoint: true,
	})
	if client.httpClient.Timeout != 3*time.Second {
		t.Fatalf("client timeout = %v, want 3s", client.httpClient.Timeout)
	}
	if client.httpClient.CheckRedirect == nil {
		t.Fatal("CheckRedirect is nil")
	}

	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.httpClient.Transport)
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

func TestClientHTTPClientRejectsPrivateRedirect(t *testing.T) {
	origAllow := testAllowPrivate
	testAllowPrivate = false
	defer func() { testAllowPrivate = origAllow }()

	client := NewClient(ClientConfig{})
	req, err := http.NewRequest(http.MethodPost, "http://127.0.0.1/v1/chat/completions", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := client.httpClient.CheckRedirect(req, nil); err == nil {
		t.Fatal("expected private redirect rejection")
	}
}

func TestNewClientValidatedRejectsPrivateEndpoint(t *testing.T) {
	origAllow := testAllowPrivate
	testAllowPrivate = false
	defer func() { testAllowPrivate = origAllow }()

	_, err := NewClientValidated(ClientConfig{BaseURL: "http://127.0.0.1:8080/v1"})
	if err == nil {
		t.Fatal("expected private endpoint rejection")
	}
	if !strings.Contains(err.Error(), "private/loopback") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewClientValidatedRejectsCredentialEndpoint(t *testing.T) {
	origAllow := testAllowPrivate
	testAllowPrivate = false
	defer func() { testAllowPrivate = origAllow }()

	_, err := NewClientValidated(ClientConfig{BaseURL: "https://token@example.com/v1"})
	if err == nil {
		t.Fatal("expected credential-bearing endpoint rejection")
	}
	if !strings.Contains(err.Error(), "userinfo") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewClientValidatedAllowsPrivateEndpointWithExplicitOptIn(t *testing.T) {
	client, err := NewClientValidated(ClientConfig{
		BaseURL:              "http://127.0.0.1:8080/v1",
		AllowPrivateEndpoint: true,
	})
	if err != nil {
		t.Fatalf("NewClientValidated: %v", err)
	}
	if client == nil {
		t.Fatal("expected client")
	}
}

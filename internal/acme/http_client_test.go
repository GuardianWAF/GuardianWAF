package acme

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestACMEHTTPClientDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()

	redirected := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/directory":
			http.Redirect(w, r, "/redirected", http.StatusFound)
		case "/redirected":
			redirected = true
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	resp, err := newACMEHTTPClient().Get(srv.URL + "/directory")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if redirected {
		t.Fatal("ACME client followed redirect")
	}
}

func TestNewACMEHTTPClientHasTransportTimeouts(t *testing.T) {
	t.Parallel()

	client := newACMEHTTPClient()
	if client.Timeout != 30*time.Second {
		t.Fatalf("client timeout = %v, want 30s", client.Timeout)
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

func TestNewClientUsesHardenedHTTPClient(t *testing.T) {
	t.Parallel()

	client := NewClient(LetsEncryptStaging)
	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.httpClient.Transport)
	}
	if transport.ResponseHeaderTimeout == 0 {
		t.Fatal("ResponseHeaderTimeout is zero")
	}
	if client.httpClient.CheckRedirect == nil {
		t.Fatal("CheckRedirect is nil")
	}
}

func TestACMEEndpointMustStayOnDirectoryOrigin(t *testing.T) {
	t.Parallel()

	client := NewClient("https://acme.example/directory")
	for _, test := range []struct {
		name    string
		url     string
		wantErr bool
	}{
		{name: "same origin", url: "https://acme.example/new-order"},
		{name: "explicit default port", url: "https://acme.example:443/new-order"},
		{name: "different host", url: "https://127.0.0.1/new-order", wantErr: true},
		{name: "scheme downgrade", url: "http://acme.example/new-order", wantErr: true},
		{name: "different port", url: "https://acme.example:8443/new-order", wantErr: true},
		{name: "credentials", url: "https://user:pass@acme.example/new-order", wantErr: true},
		{name: "fragment", url: "https://acme.example/new-order#internal", wantErr: true},
		{name: "non HTTP scheme", url: "file:///etc/passwd", wantErr: true},
		{name: "relative", url: "/new-order", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := client.validateEndpoint(test.url)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateEndpoint(%q) error = %v, wantErr %v", test.url, err, test.wantErr)
			}
		})
	}
}

func TestACMEServerProvidedNonceCannotChangeOrigin(t *testing.T) {
	t.Parallel()

	client := NewClient("https://acme.example/directory")
	client.directory = &directory{NewNonce: "http://127.0.0.1/latest/meta-data"}
	_, err := client.getNonce()
	if err == nil {
		t.Fatal("expected cross-origin nonce endpoint to be rejected")
	}
	if got := err.Error(); !strings.Contains(got, "does not match directory origin") {
		t.Fatalf("unexpected error: %v", err)
	}
}

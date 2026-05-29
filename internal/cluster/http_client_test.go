package cluster

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClusterCoordinationHTTPClientDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()

	redirected := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cluster/join":
			http.Redirect(w, r, "/redirected", http.StatusFound)
		case "/redirected":
			redirected = true
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	resp, err := newClusterCoordinationHTTPClient().Get(srv.URL + "/cluster/join")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if redirected {
		t.Fatal("cluster coordination client followed redirect")
	}
}

func TestClusterCoordinationHTTPClientHasTransportTimeouts(t *testing.T) {
	t.Parallel()

	client := newClusterCoordinationHTTPClient()
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

func TestNewUsesClusterCoordinationHTTPClient(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", c.httpClient.Transport)
	}
	if transport.ResponseHeaderTimeout == 0 {
		t.Fatal("ResponseHeaderTimeout is zero")
	}
	if c.httpClient.CheckRedirect == nil {
		t.Fatal("CheckRedirect is nil")
	}
}

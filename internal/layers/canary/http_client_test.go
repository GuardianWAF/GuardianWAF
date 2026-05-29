package canary

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHealthCheckHTTPClientDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()

	redirected := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			http.Redirect(w, r, "/ready", http.StatusFound)
		case "/ready":
			redirected = true
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	resp, err := newHealthCheckHTTPClient(time.Second).Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if redirected {
		t.Fatal("health check client followed redirect")
	}
}

func TestNewHealthCheckHTTPClientHasTransportTimeouts(t *testing.T) {
	t.Parallel()

	client := newHealthCheckHTTPClient(2 * time.Second)
	if client.Timeout != 2*time.Second {
		t.Fatalf("client timeout = %v, want 2s", client.Timeout)
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
	if transport.TLSHandshakeTimeout != 2*time.Second {
		t.Fatalf("TLSHandshakeTimeout = %v, want 2s", transport.TLSHandshakeTimeout)
	}
	if transport.ResponseHeaderTimeout != 2*time.Second {
		t.Fatalf("ResponseHeaderTimeout = %v, want 2s", transport.ResponseHeaderTimeout)
	}
	if transport.ExpectContinueTimeout != time.Second {
		t.Fatalf("ExpectContinueTimeout = %v, want 1s", transport.ExpectContinueTimeout)
	}
	if transport.IdleConnTimeout != 30*time.Second {
		t.Fatalf("IdleConnTimeout = %v, want 30s", transport.IdleConnTimeout)
	}
}

func TestNewUsesHardenedHealthCheckHTTPClient(t *testing.T) {
	t.Parallel()

	c, err := New(&Config{
		Enabled: true,
		HealthCheck: HealthCheckConfig{
			Enabled: false,
			Timeout: time.Second,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

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

func TestPerformHealthCheck_RedirectIsUnhealthy(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			http.Redirect(w, r, "/ready", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := New(&Config{
		Enabled: true,
		HealthCheck: HealthCheckConfig{
			Enabled: false,
			Timeout: time.Second,
			Path:    "/healthz",
		},
		CanaryUpstream: srv.URL,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	c.healthCount.Store(1)
	c.performHealthCheck()
	if c.healthCount.Load() != 0 {
		t.Fatalf("healthCount = %d, want 0 after redirect", c.healthCount.Load())
	}
}

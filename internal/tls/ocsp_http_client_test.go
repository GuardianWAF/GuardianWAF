package tls

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestOCSPHTTPClientDoesNotFollowRedirects(t *testing.T) {
	targetHits := atomic.Int64{}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(extraBuildValidOCSPResponse())
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/ocsp", http.StatusFound)
	}))
	defer redirector.Close()

	_, _, cert := extraGenerateCertWithAIA(t, redirector.URL, "redirect-ocsp.example.com")
	_, err := FetchOCSPResponse(cert, cert)
	if err == nil {
		t.Fatal("expected redirected OCSP response to fail")
	}
	if got := targetHits.Load(); got != 0 {
		t.Fatalf("OCSP client followed redirect to target server %d times", got)
	}
}

func TestNewOCSPHTTPClientHasTransportTimeouts(t *testing.T) {
	client := newOCSPHTTPClient()
	if client.Timeout != 10*time.Second {
		t.Fatalf("client timeout = %v, want 10s", client.Timeout)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.ResponseHeaderTimeout != 10*time.Second {
		t.Fatalf("response header timeout = %v, want 10s", transport.ResponseHeaderTimeout)
	}
	if transport.TLSHandshakeTimeout != 5*time.Second {
		t.Fatalf("TLS handshake timeout = %v, want 5s", transport.TLSHandshakeTimeout)
	}
	if client.CheckRedirect == nil {
		t.Fatal("expected CheckRedirect to be configured")
	}
}

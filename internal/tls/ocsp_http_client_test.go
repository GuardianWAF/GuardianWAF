package tls

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	ocspHTTPClient = newTestOCSPHTTPClient()
	os.Exit(m.Run())
}

func newTestOCSPHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

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

func TestOCSP_newOCSPHTTPClient_Timeout(t *testing.T) {
	client := newOCSPHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if client.Timeout != 10*time.Second {
		t.Fatalf("client timeout = %v, want 10s", client.Timeout)
	}
	if transport.IdleConnTimeout != 30*time.Second {
		t.Fatalf("idle conn timeout = %v, want 30s", transport.IdleConnTimeout)
	}
	if transport.ExpectContinueTimeout != time.Second {
		t.Fatalf("expect continue timeout = %v, want 1s", transport.ExpectContinueTimeout)
	}
}

func TestNewOCSPHTTPClientRejectsPrivateResolvedIPs(t *testing.T) {
	client := newOCSPHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.DialContext == nil {
		t.Fatal("expected DialContext to be configured")
	}

	_, err := transport.DialContext(context.Background(), "tcp", "127.0.0.1:80")
	if err == nil {
		t.Fatal("expected private OCSP responder dial to be rejected")
	}
	if !strings.Contains(err.Error(), "OCSP SSRF dial") {
		t.Fatalf("expected OCSP SSRF dial error, got %v", err)
	}
}

func TestReadOCSPResponseRejectsOversizedValidPrefix(t *testing.T) {
	valid := extraBuildValidOCSPResponse()
	body, err := readOCSPResponse(io.MultiReader(
		bytes.NewReader(valid),
		strings.NewReader(strings.Repeat(" ", maxOCSPResponseBytes)),
	))
	if err == nil {
		t.Fatal("expected oversized OCSP response to fail")
	}
	if body != nil {
		t.Fatalf("expected no body on oversized OCSP response, got %d bytes", len(body))
	}
	if !strings.Contains(err.Error(), "OCSP response exceeds") {
		t.Fatalf("expected OCSP response size error, got %v", err)
	}
}

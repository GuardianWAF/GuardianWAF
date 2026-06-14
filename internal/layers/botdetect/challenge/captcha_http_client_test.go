package challenge

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type captchaRewriteTransport struct {
	target *url.URL
}

func (t *captchaRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = t.target.Scheme
	req.URL.Host = t.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

func TestCaptchaVerificationHTTPClient_DoesNotFollowRedirects(t *testing.T) {
	targetHits := atomic.Int64{}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/siteverify", http.StatusFound)
	}))
	defer redirector.Close()

	parsed, err := url.Parse(redirector.URL)
	if err != nil {
		t.Fatalf("parse redirector URL: %v", err)
	}

	provider := NewHCaptcha(HCaptchaConfig{SecretKey: "secret", SiteKey: "site"})
	provider.client.Transport = &captchaRewriteTransport{target: parsed}

	_, err = provider.VerifyToken("token", "203.0.113.10")
	if err == nil {
		t.Fatal("expected redirected verification response to fail")
	}
	if got := targetHits.Load(); got != 0 {
		t.Fatalf("CAPTCHA verification client followed redirect to target server %d times", got)
	}
}

func TestCaptchaVerificationResponseRejectsOversizeBody(t *testing.T) {
	_, err := readCaptchaVerificationResponse(io.NopCloser(strings.NewReader(strings.Repeat("a", captchaVerificationMaxResponseBytes+1))))
	if err == nil {
		t.Fatal("expected oversize CAPTCHA response to be rejected")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize response rejected with unexpected error: %v", err)
	}
}

func TestCaptchaVerificationHTTPClient_HasTransportTimeouts(t *testing.T) {
	client := newCaptchaVerificationHTTPClient(7 * time.Second)
	if client.Timeout != 7*time.Second {
		t.Fatalf("client timeout = %v, want 7s", client.Timeout)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.ResponseHeaderTimeout != 7*time.Second {
		t.Fatalf("response header timeout = %v, want 7s", transport.ResponseHeaderTimeout)
	}
	if transport.TLSHandshakeTimeout != 7*time.Second {
		t.Fatalf("TLS handshake timeout = %v, want 7s", transport.TLSHandshakeTimeout)
	}
	if client.CheckRedirect == nil {
		t.Fatal("expected CheckRedirect to be configured")
	}
}

func TestCaptchaVerificationHTTPClient_RejectsPrivateDialTargets(t *testing.T) {
	client := newCaptchaVerificationHTTPClient(7 * time.Second)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.DialContext == nil {
		t.Fatal("expected DialContext to be configured")
	}

	_, err := transport.DialContext(context.Background(), "tcp", "127.0.0.1:443")
	if err == nil {
		t.Fatal("expected private CAPTCHA dial target to be rejected")
	}
	if !strings.Contains(err.Error(), "CAPTCHA SSRF dial") {
		t.Fatalf("private dial rejected with unexpected error: %v", err)
	}
}

func TestCaptchaConstructorsUseVerificationHTTPClient(t *testing.T) {
	hcaptcha := NewHCaptcha(HCaptchaConfig{SecretKey: "secret", SiteKey: "site"})
	if hcaptcha.client == nil || hcaptcha.client.CheckRedirect == nil {
		t.Fatal("expected hCaptcha client to disable redirects")
	}
	if _, ok := hcaptcha.client.Transport.(*http.Transport); !ok {
		t.Fatalf("hCaptcha transport type = %T, want *http.Transport", hcaptcha.client.Transport)
	}

	turnstile := NewTurnstile(TurnstileConfig{SecretKey: "secret", SiteKey: "site"})
	if turnstile.client == nil || turnstile.client.CheckRedirect == nil {
		t.Fatal("expected Turnstile client to disable redirects")
	}
	if _, ok := turnstile.client.Transport.(*http.Transport); !ok {
		t.Fatalf("Turnstile transport type = %T, want *http.Transport", turnstile.client.Transport)
	}
}

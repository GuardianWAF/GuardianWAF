package challenge

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type errReader struct{}

func (errReader) Read(_ []byte) (int, error) {
	return 0, errors.New("boom")
}

func TestReadCaptchaVerificationResponse_ReadError(t *testing.T) {
	_, err := readCaptchaVerificationResponse(errReader{})
	if err == nil {
		t.Fatal("expected read error")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCaptchaPublicOnlyDialContext_DNSFailure(t *testing.T) {
	dial := captchaPublicOnlyDialContext(50 * time.Millisecond)
	_, err := dial(context.Background(), "tcp", "nonexistent-challenge-host.invalid:443")
	if err == nil {
		t.Fatal("expected DNS lookup failure")
	}
	if !strings.Contains(err.Error(), "DNS lookup failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCaptchaPublicOnlyDialContext_NoPortRejectsPrivateHost(t *testing.T) {
	dial := captchaPublicOnlyDialContext(50 * time.Millisecond)
	_, err := dial(context.Background(), "tcp", "localhost")
	if err == nil {
		t.Fatal("expected localhost without port to be rejected")
	}
	if !strings.Contains(err.Error(), "no valid public IPs") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCaptchaPublicOnlyDialContext_AttemptsPublicIP(t *testing.T) {
	dial := captchaPublicOnlyDialContext(50 * time.Millisecond)
	_, err := dial(context.Background(), "tcp", "1.1.1.1:81")
	if err == nil {
		t.Fatal("expected dialing unroutable test port to fail")
	}
	if strings.Contains(err.Error(), "DNS lookup failed") || strings.Contains(err.Error(), "no valid public IPs") {
		t.Fatalf("expected public IP dial attempt, got helper error: %v", err)
	}
}

func TestTurnstile_VerifyToken_OversizedResponse(t *testing.T) {
	overflow := strings.Repeat("a", captchaVerificationMaxResponseBytes)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"padding":"` + overflow + `"}`))
	}))
	defer srv.Close()

	p := &TurnstileProvider{
		secretKey: "test-secret",
		siteKey:   "test-site",
		client:    srv.Client(),
	}

	_, err := p.verifyTokenWithURL("valid-token", "", srv.URL)
	if err == nil {
		t.Fatal("expected error for oversized response")
	}
	if !strings.Contains(err.Error(), "failed to read response") {
		t.Fatalf("unexpected error: %v", err)
	}
}

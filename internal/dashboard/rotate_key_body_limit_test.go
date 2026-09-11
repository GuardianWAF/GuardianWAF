package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The contract: the rotation endpoint caps its JSON body like every other
// JSON endpoint in this package — an oversized body is rejected with 413
// BEFORE decoding, so an authenticated client cannot force unbounded
// allocation by padding current_key.
func TestRotateKeyOversizedBodyRejected(t *testing.T) {
	// Control A: a normal-size valid rotation still succeeds (200).
	{
		d := newTestDashboard(t, "original-key")
		body := `{"current_key":"original-key","new_key":"rotated-key-12345"}`
		req := authenticatedRequest("POST", "/api/v1/rotate-key", body, "original-key")
		w := httptest.NewRecorder()
		d.mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("CONTROL FAILED: valid small rotation expected 200, got %d: %s", w.Code, w.Body.String())
		}
	}

	// Fresh dashboard: the control above rotated the key holder.
	d := newTestDashboard(t, "original-key")

	// The oversized body: current_key padded well past any sane key size.
	huge := strings.Repeat("A", 64*1024)
	body := `{"current_key":"` + huge + `","new_key":"rotated-key-12345"}`
	req := authenticatedRequest("POST", "/api/v1/rotate-key", body, "original-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("FAIL rotate-key-oversized-body: an oversized rotation body must be rejected with 413 before decoding; got %d (body len %d). handleRotateKey decodes unbounded input, diverging from handleLoginSubmit's 4 KiB cap (login_handlers.go:114) and the 1 MiB JSON decoders every other handler uses.", w.Code, len(body))
	}

	// Control B: a normal-size WRONG current key still yields 403 — the cap
	// must not change the small-body contract.
	{
		small := `{"current_key":"wrong-key-value","new_key":"rotated-key-12345"}`
		req := authenticatedRequest("POST", "/api/v1/rotate-key", small, "original-key")
		w := httptest.NewRecorder()
		d.mux.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("CONTROL FAILED: small wrong-key rotation expected 403, got %d: %s", w.Code, w.Body.String())
		}
	}
}

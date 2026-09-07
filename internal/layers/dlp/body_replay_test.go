package dlp

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression tests: the DLP layer must not consume bytes from the shared
// request body stream without restoring them. Engine.Middleware forwards the
// same *http.Request to the downstream handler / reverse proxy after the
// pipeline runs, so any bytes the DLP scan drains from ctx.Request.Body are
// lost for the upstream application (truncated body, stale Content-Length).

type nopEventStore struct{}

func (nopEventStore) Store(event engine.Event) error { return nil }
func (nopEventStore) Close() error                   { return nil }

type nopEventBus struct{}

func (nopEventBus) Subscribe(ch chan<- engine.Event) {}
func (nopEventBus) Publish(event engine.Event)       {}
func (nopEventBus) Close()                           {}

// newDLPTestEngine builds a real engine whose pipeline contains only the DLP
// layer — the same *Layer type the serve binary wires via layerregistry
// buildDLP — and an httptest downstream that echoes whatever body it receives.
func newDLPTestEngine(t *testing.T, dlpCfg *Config) (*engine.Engine, *httptest.Server) {
	t.Helper()

	cfg := config.DefaultConfig()
	cfg.Events.Storage = "memory"

	eng, err := engine.NewEngine(cfg, nopEventStore{}, nopEventBus{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(func() { eng.Close() })

	eng.AddLayer(engine.OrderedLayer{Layer: NewLayer(dlpCfg), Order: engine.OrderDLP})

	var downstreamHandler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "downstream body read: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})

	downstream := httptest.NewServer(downstreamHandler)
	t.Cleanup(downstream.Close)

	mw := httptest.NewServer(eng.Middleware(downstreamHandler))
	t.Cleanup(mw.Close)

	return eng, mw
}

func postBody(t *testing.T, url, contentType, body string) string {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST through middleware: %v", err)
	}
	defer resp.Body.Close()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("downstream status = %d, want 200 (body: %q)", resp.StatusCode, got)
	}
	return string(got)
}

// TestProcessPreservesRequestBodyForDownstream proves the full body reaches
// the downstream handler when the DLP scan passes a scannable request.
// Body is smaller than the scan limit, so the pre-fix bug consumed it whole.
func TestProcessPreservesRequestBodyForDownstream(t *testing.T) {
	_, mw := newDLPTestEngine(t, &Config{
		Enabled:     true,
		ScanRequest: true,
		MaxBodySize: 1024 * 1024,
		Patterns:    []string{"credit_card"},
	})

	body := `{"note":"hello world","items":[1,2,3],"more":"padding padding padding"}`
	got := postBody(t, mw.URL, "application/json", body)

	if got != body {
		t.Fatalf("FAIL: downstream received truncated body: got %d bytes (%q), want %d bytes", len(got), got, len(body))
	}
}

// TestProcessPreservesBodyLargerThanScanLimit covers the boundary where the
// DLP scan limit is smaller than the body: the scan consumes its full budget
// from the shared stream, so the downstream loses exactly that prefix.
func TestProcessPreservesBodyLargerThanScanLimit(t *testing.T) {
	_, mw := newDLPTestEngine(t, &Config{
		Enabled:     true,
		ScanRequest: true,
		MaxBodySize: 16,
		Patterns:    []string{"credit_card"},
	})

	body := `{"data":"` + strings.Repeat("x", 200) + `"}`
	got := postBody(t, mw.URL, "application/json", body)

	if got != body {
		t.Fatalf("FAIL: downstream received truncated body: got %d bytes, want %d bytes (prefix lost: %q)", len(got), len(body), body[:min(len(body)-len(got), len(body))])
	}
}

// TestProcessPassesNonScannableBodyUntouched guards the early-return paths:
// non-scannable content types must not consume anything from the stream.
func TestProcessPassesNonScannableBodyUntouched(t *testing.T) {
	_, mw := newDLPTestEngine(t, &Config{
		Enabled:     true,
		ScanRequest: true,
		MaxBodySize: 1024 * 1024,
		Patterns:    []string{"credit_card"},
	})

	body := strings.Repeat("\x00\x01binarypayload", 8)
	got := postBody(t, mw.URL, "application/octet-stream", body)

	if !bytes.Equal([]byte(got), []byte(body)) {
		t.Fatalf("FAIL: non-scannable body altered downstream: got %d bytes, want %d bytes", len(got), len(body))
	}
}

// TestProcessForwardsFullBodyWhenPIIDetected covers the scan-hit path with
// BlockOnMatch=false: the request passes, so the body must still be complete
// for the upstream.
func TestProcessForwardsFullBodyWhenPIIDetected(t *testing.T) {
	_, mw := newDLPTestEngine(t, &Config{
		Enabled:      true,
		ScanRequest:  true,
		BlockOnMatch: false,
		MaxBodySize:  1024 * 1024,
		Patterns:     []string{"credit_card"},
	})

	body := `{"refund_to":"4111 1111 1111 1111","note":"card on file for customer 42"}`
	got := postBody(t, mw.URL, "application/json", body)

	if got != body {
		t.Fatalf("FAIL: PII-bearing passing request truncated downstream: got %d bytes, want %d bytes", len(got), len(body))
	}
}

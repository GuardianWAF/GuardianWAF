package dlp

// Regression (round 2026-09-24-r21-dlp-response-hook): Layer.ScanResponse
// and maskContent were fully implemented (including the sorted-substitution
// fix) but had ZERO production callers — EngineLayer.Process handles
// request bodies only, and the engine's response path applied only
// ctx.ResponseMaskFn (owned by the response layer) and
// ctx.ClientsideBodyXform. The yaml knobs scan_response/mask_response
// (defaulting TRUE) were therefore silently inert in serve mode: response
// PII was never masked. Post-fix the DLP layer registers a DLPBodyXform
// response hook when ScanResponse is enabled (mirroring the
// ClientsideBodyXform seam); the engine composes it clientside-first so
// the mask applies to the final body, and ScanResponse records alerts with
// masked values only.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestResponsePIIMaskedWhenConfigured(t *testing.T) {
	dlpCfg := &Config{
		Enabled:      true,
		ScanRequest:  true,
		ScanResponse: true,
		MaskResponse: true,
		MaxBodySize:  1024 * 1024,
		Patterns:     []string{"credit_card"},
	}

	cfg := config.DefaultConfig()
	cfg.Events.Storage = "memory"
	eng, err := engine.NewEngine(cfg, nopEventStore{}, nopEventBus{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(func() { eng.Close() })

	eng.AddLayer(engine.OrderedLayer{Layer: NewLayer(dlpCfg), Order: engine.OrderDLP})

	card := "4111111111111111"
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"refund_to":"` + card + `"}`))
	})
	mw := httptest.NewServer(eng.Middleware(next))
	t.Cleanup(mw.Close)

	req, err := http.NewRequest(http.MethodGet, mw.URL+"/balance", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET through middleware: %v", err)
	}
	defer resp.Body.Close()
	got := new(strings.Builder)
	_, _ = io.Copy(got, resp.Body)

	if strings.Contains(got.String(), card) {
		t.Fatalf("response leaked the raw card number despite mask_response=true: %q", got.String())
	}
}

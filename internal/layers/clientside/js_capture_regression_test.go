package clientside

// Regression (round 2026-09-24-r23-js-capture-gap): the engine's response
// capture gate (engine.response_writer.go shouldCapture) excluded
// application/javascript, so standalone .js responses — the stage-2 Magecart
// payload shape, and the content type the clientside scanner's own isJS
// contract (layer.go) explicitly covers — never reached the response body
// hooks: no Magecart detection and no DLP masking for that content type.
// The gate now includes application/javascript to match the scanner
// contract; text/javascript was already covered via the text/ prefix.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestApplicationJavascriptResponsesAreAnalyzed(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Events.Storage = "memory"
	eng, err := engine.NewEngine(cfg, r22NopEventStore{}, r22NopEventBus{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(func() { eng.Close() })

	clientCfg := DefaultConfig()
	clientCfg.Enabled = true
	clientCfg.Mode = "block"
	clientCfg.MagecartDetection.Enabled = true
	clientCfg.MagecartDetection.DetectSuspiciousDomains = true
	clientCfg.MagecartDetection.SuspiciousPatterns = []string{"evil-exfil-collector"}
	eng.AddLayer(engine.OrderedLayer{Layer: NewLayer(clientCfg), Order: engine.OrderClientSide})

	payload := `<script src="https://cdn.example/evil-exfil-collector.js"></script>`
	for _, tc := range []struct{ ct, label string }{
		{"application/javascript", "js-case"},
		{"text/javascript", "text-control"},
	} {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", tc.ct)
			_, _ = w.Write([]byte(payload))
		})
		mw := httptest.NewServer(eng.Middleware(next))

		resp, err := http.Get(mw.URL + "/static/app.js")
		if err != nil {
			t.Fatalf("%s: GET: %v", tc.label, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		mw.Close()

		got := string(body)
		if strings.Contains(got, "evil-exfil-collector") {
			t.Fatalf("%s: skimmer script leaked raw despite block mode: %q", tc.label, got)
		}
		if !strings.Contains(got, "Blocked by Client-Side Protection") {
			t.Fatalf("%s: expected the block page, got: %q", tc.label, got)
		}
	}
}

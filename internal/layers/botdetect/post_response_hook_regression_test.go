package botdetect

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

// Regression: failed upstream responses must reach the behavioural error counter
// through the real request path.
//
// Process records every request with isError=false (the outcome is unknown at
// request time), so the ErrorRateThreshold can only fire if the layer is told
// the outcome afterwards. PostProcess existed but had no production caller — the
// engine never invoked it — so the threshold could never fire. The layer now
// registers engine.RequestContext.PostResponseHook during Process and the engine
// invokes it with success = upstream status < 400.
func TestFailedResponsesCountAsErrorsThroughEngine(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Mode:    "enforce",
		TLSFingerprint: TLSFingerprintConfig{
			Enabled: false,
		},
		UserAgent: UAConfig{
			Enabled: false,
		},
		Behavior: BehaviorAnalysisConfig{
			Enabled:            true,
			Window:             time.Minute,
			RPSThreshold:       1000, // high: only the error rate may fire
			ErrorRateThreshold: 30,
			UniquePathsPerMin:  1000, // high: same path in every request
			TimingStdDevMs:     0,    // disabled: no machine-timing signal
		},
	})

	eng, err := engine.NewEngine(config.DefaultConfig(), events.NewMemoryStore(64), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close() })
	eng.AddLayer(engine.OrderedLayer{Layer: layer, Order: engine.OrderBotDetect})

	upstreamStatus := http.StatusOK
	srv := httptest.NewServer(eng.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(upstreamStatus)
	})))
	t.Cleanup(srv.Close)

	get := func(t *testing.T) {
		t.Helper()
		resp, err := srv.Client().Get(srv.URL + "/login")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
	}

	// Control: successful responses must not be counted as errors.
	for range 4 {
		get(t)
	}
	if _, findings := layer.BehaviorMgr().Analyze("127.0.0.1"); containsErrorRate(findings) {
		t.Fatalf("successful responses were counted as errors: %v", findings)
	}

	// Every request now fails upstream: 4/4 = 100% > ErrorRateThreshold.
	upstreamStatus = http.StatusInternalServerError
	for range 4 {
		get(t)
	}

	score, findings := layer.BehaviorMgr().Analyze("127.0.0.1")
	if !containsErrorRate(findings) {
		t.Fatalf("failed upstream responses did not reach the error-rate analysis "+
			"(score=%d findings=%v) — the post-response outcome never reached the layer", score, findings)
	}
}

func containsErrorRate(findings []string) bool {
	for _, f := range findings {
		if strings.Contains(f, "high error rate") {
			return true
		}
	}
	return false
}

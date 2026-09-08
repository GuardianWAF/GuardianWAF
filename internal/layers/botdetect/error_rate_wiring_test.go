package botdetect

import (
	"net"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression: the layer's Process records every request with isError=false
// (the response outcome is unknown at request time), and the layer had no
// post-process hook — so bucket errors were never incremented and the
// ErrorRateThreshold detection could never fire, regardless of config.
func TestErrorRateDetectionWiring(t *testing.T) {
	l := NewLayer(&Config{
		Enabled: true,
		Mode:    "enforce",
		Behavior: BehaviorAnalysisConfig{
			Enabled:            true,
			Window:             time.Minute,
			RPSThreshold:       10000, // keep the RPS check out of the way
			UniquePathsPerMin:  0,     // disabled
			ErrorRateThreshold: 10,    // >10% errors → finding
			TimingStdDevMs:     0,     // disabled
		},
	})
	ip := net.ParseIP("10.0.0.5")

	for i := 0; i < 60; i++ {
		ctx := &engine.RequestContext{Method: "GET", Path: "/", ClientIP: ip, Accumulator: engine.NewScoreAccumulator(3)}
		l.Process(ctx)
		l.PostProcess(ctx, false) // every request errors
	}

	_, findings := l.behavior.Analyze(ip.String())
	found := false
	for _, f := range findings {
		if f == "high error rate detected" {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: error-rate finding never fired through the layer (findings=%v) — the outcome wiring is missing", findings)
	}
}

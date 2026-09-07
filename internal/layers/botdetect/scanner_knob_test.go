package botdetect

import (
	"net"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression tests: UserAgent.BlockKnownScanners must be honored. The knob
// was plumbed through YAML, the dashboard, and the layer registry (default
// true) but never read by the detection logic, so flipping it changed
// nothing — scanner User-Agents were always escalated to a block-tier score
// (85 >= 80) in enforce mode.

func newScannerKnobLayer(t *testing.T, blockScanners bool) *Layer {
	t.Helper()
	cfg := Config{
		Enabled:        true,
		Mode:           "enforce",
		TLSFingerprint: TLSFingerprintConfig{Enabled: false},
		UserAgent: UAConfig{
			Enabled:            true,
			BlockKnownScanners: blockScanners,
		},
		Behavior: BehaviorAnalysisConfig{Enabled: false},
	}
	return NewLayer(&cfg)
}

func scannerKnobRequest(t *testing.T, layer *Layer, ua string) engine.LayerResult {
	t.Helper()
	ctx := &engine.RequestContext{
		ClientIP:    net.ParseIP("192.0.2.10"),
		Method:      "GET",
		Path:        "/",
		Headers:     map[string][]string{"User-Agent": {ua}},
		Accumulator: engine.NewScoreAccumulator(2),
	}
	result := layer.Process(ctx)
	engine.ReleaseContext(ctx)
	return result
}

func TestBlockKnownScannersFalseSuppressesEscalation(t *testing.T) {
	blocked := newScannerKnobLayer(t, true)
	notBlocked := newScannerKnobLayer(t, false)

	onResult := scannerKnobRequest(t, blocked, "sqlmap/1.5#stable")
	if onResult.Action != engine.ActionBlock {
		t.Fatalf("FAIL: BlockKnownScanners=true should escalate a scanner UA to a block (score 85 >= 80), got %v", onResult.Action)
	}

	offResult := scannerKnobRequest(t, notBlocked, "sqlmap/1.5#stable")
	if offResult.Action == engine.ActionBlock {
		t.Fatalf("FAIL: BlockKnownScanners=false has no effect — scanner UA still escalated to a block (action = %v, findings = %+v)", offResult.Action, offResult.Findings)
	}
}

// Boundary: disabling the scanner escalation must not suppress ordinary bot
// detection — non-scanner bot UAs are still scored.
func TestBlockKnownScannersFalseStillScoresOrdinaryBots(t *testing.T) {
	layer := newScannerKnobLayer(t, false)

	result := scannerKnobRequest(t, layer, "unknownbot/1.0 (crawler)")
	if result.Score == 0 || len(result.Findings) == 0 {
		t.Fatal("FAIL: ordinary bot UA no longer scored when BlockKnownScanners=false")
	}
}

// Control: normal browsers are never flagged, regardless of the knob.
func TestNormalBrowserUnaffectedByScannerKnob(t *testing.T) {
	layer := newScannerKnobLayer(t, true)

	result := scannerKnobRequest(t, layer, "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0")
	if result.Action != engine.ActionPass || len(result.Findings) != 0 {
		t.Fatalf("FAIL: normal browser flagged: %v / %+v", result.Action, result.Findings)
	}
}

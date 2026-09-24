package botdetect

// Regression (round 2026-09-24-r18-ua-multivalue): analyzeUA scored ONLY
// vals[0] of the User-Agent header. The engine preserves every transmitted
// value, and backend parsers disagree on which one they surface (Go
// first-wins, PHP/Python last-wins) — scoring only vals[0] lets the
// attacker pick which UA the WAF sees by header ordering: a scanner UA
// riding as the SECOND value was never analyzed, so BlockKnownScanners
// never fired. Post-fix analyzeUA loops all values with any-match
// semantics; the BlockEmpty/BlockKnownScanners suppression filters apply
// per value (the round-20/81 multi-value family).

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestUAScannerDetectionSeesAllValues(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Mode:    "enforce",
		UserAgent: UAConfig{
			Enabled:            true,
			BlockEmpty:         true,
			BlockKnownScanners: true,
		},
	})

	// Control: a single scanner UA blocks in enforce mode (score 85 >= 80).
	single := &engine.RequestContext{
		Method:      "GET",
		Path:        "/",
		Accumulator: engine.NewScoreAccumulator(2),
		Headers: map[string][]string{
			"User-Agent": {"sqlmap/1.7"},
		},
	}
	if res := layer.Process(single); res.Action != engine.ActionBlock {
		t.Fatalf("control: single scanner UA did not block: action=%v score=%d", res.Action, res.Score)
	}

	// The fixed defect: the same scanner UA as the SECOND User-Agent value,
	// behind a clean browser UA.
	dup := &engine.RequestContext{
		Method:      "GET",
		Path:        "/",
		Accumulator: engine.NewScoreAccumulator(2),
		Headers: map[string][]string{
			"User-Agent": {"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "sqlmap/1.7"},
		},
	}
	if res := layer.Process(dup); res.Action != engine.ActionBlock {
		t.Fatalf("scanner UA riding as the second User-Agent value evaded detection: action=%v score=%d", res.Action, res.Score)
	}
}

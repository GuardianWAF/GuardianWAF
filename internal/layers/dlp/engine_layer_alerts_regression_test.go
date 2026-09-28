package dlp

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// The EngineLayer is the engine-context integration of the DLP layer. Its
// Process must honor the same alerts contract as Layer.Process (the r90-era
// contract): every unsafe scan records an alert with the action the layer
// decided and the MASKED match value, never the raw PII.
func TestEngineLayer_Process_RecordsAlerts(t *testing.T) {
	el := NewEngineLayer(&Config{
		Enabled:      true,
		ScanRequest:  true,
		BlockOnMatch: true,
		Patterns:     []string{"credit_card"},
	})
	el.scanRequest = true

	ctx := &engine.RequestContext{
		Method: "POST",
		Path:   "/api/checkout",
		Body:   []byte("card 4111111111111111 and 5500005555555559"),
		Headers: map[string][]string{
			"Content-Type": {"text/plain"},
		},
		Accumulator: engine.NewScoreAccumulator(2),
	}

	res := el.Process(ctx)
	if res.Action != engine.ActionBlock {
		t.Fatalf("expected block on PII with BlockOnMatch, got %v (score %d)", res.Action, res.Score)
	}

	alerts := el.GetAlerts(100, "")
	if len(alerts) != 2 {
		t.Fatalf("expected 2 recorded alerts (one per match), got %d", len(alerts))
	}
	for _, a := range alerts {
		if a.Action != "block" {
			t.Errorf("alert action = %q, want block", a.Action)
		}
		if a.Path != "/api/checkout" {
			t.Errorf("alert path = %q, want /api/checkout", a.Path)
		}
		if a.MatchedValue == "4111111111111111" || a.MatchedValue == "5500005555555559" {
			t.Errorf("alert leaked raw PII: %q", a.MatchedValue)
		}
	}
}

// The unlocked el.config.Enabled read was a latent race vs concurrent config
// mutation; Process must read through the same snapshotConfig lock the live
// Layer.Process uses. Behavior is unchanged — this pins the locked read by
// exercising the disabled gate (and -race guards the memory model).
func TestEngineLayer_Process_DisabledUsesSnapshot(t *testing.T) {
	el := NewEngineLayer(&Config{Enabled: false, ScanRequest: true})
	el.scanRequest = true

	ctx := &engine.RequestContext{
		Method:      "POST",
		Path:        "/x",
		Body:        []byte("card 4111111111111111"),
		Accumulator: engine.NewScoreAccumulator(2),
	}

	res := el.Process(ctx)
	if res.Action != engine.ActionPass {
		t.Fatalf("disabled layer must pass, got %v", res.Action)
	}
	if alerts := el.GetAlerts(100, ""); len(alerts) != 0 {
		t.Fatalf("disabled layer recorded %d alerts, want 0", len(alerts))
	}
}

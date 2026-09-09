package dashboard

// Regression: dlpAdapter.GetPatterns/GetPattern never populated DLPPatternInfo.Enabled,
//
// Defect: dlpAdapter.GetPatterns/GetPattern construct DLPPatternInfo with
// only ID/Name/Pattern — the Enabled field is never populated, so the API
// view reports every DLP pattern as disabled regardless of registry truth.
// The dashboard lies about which patterns actually scan, and the effect of
// the DisablePattern kill-switch is invisible in the UI.

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/layers/dlp"
)

func TestDLPPatternEnabledStateVisible(t *testing.T) {
	layer := dlp.NewLayer(&dlp.Config{
		Enabled:  true,
		Patterns: []string{"credit_card", "ssn", "iban", "email", "phone", "api_key", "private_key", "passport", "tax_id"},
	})
	adapter := &dlpAdapter{layer: layer}

	patterns := adapter.GetPatterns()
	if len(patterns) == 0 {
		t.Fatal("no patterns in registry")
	}

	// The registry is the truth source; the API view must agree with it.
	enabledInRegistry := 0
	for _, rp := range layer.GetRegistry().GetAllPatterns() {
		if rp.Enabled {
			enabledInRegistry++
		}
	}
	if enabledInRegistry == 0 {
		t.Fatal("no enabled patterns in the registry — fixture error")
	}

	enabledInView := 0
	for _, p := range patterns {
		if p.Enabled {
			enabledInView++
		}
	}
	if enabledInView != enabledInRegistry {
		t.Fatalf("FAIL: API view reports %d enabled patterns but the registry has %d — DLPPatternInfo.Enabled is never populated, so the dashboard lies about which patterns scan", enabledInView, enabledInRegistry)
	}

	// The DisablePattern kill-switch's effect must be visible through the
	// same view (integration with the round-68 fix).
	first := patterns[0].ID
	if !adapter.DisablePattern(first) {
		t.Fatalf("DisablePattern(%q) returned false — fixture error", first)
	}
	for _, p := range adapter.GetPatterns() {
		if p.ID == first && p.Enabled {
			t.Fatalf("FAIL: pattern %q was disabled but the API view still reports it enabled", first)
		}
	}
}

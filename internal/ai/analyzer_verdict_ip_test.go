package ai

import (
	"testing"
	"time"
)

// Regression (hunt round 25 recorded observation, hardening): applyVerdicts
// banned whatever IP the AI response named. The prompt embeds
// attacker-influenced event data (path, query, user agent), so a manipulated
// or hallucinating model response could steer a high-confidence block verdict
// for an arbitrary address. A verdict is only actionable when it identifies
// one of the analyzed batch's own event IPs — the AutoBlockEnabled opt-in,
// the 0.7 confidence threshold, and the usage caps gate how often verdicts
// are produced, not WHICH addresses they may name.

func TestApplyVerdictsRejectsOutOfBatchIPs(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	a := NewAnalyzer(AnalyzerConfig{Enabled: true, AutoBlockEnabled: true, AutoBlockTTL: time.Hour}, store, "")

	var mb mockBlocker
	a.SetBlocker(&mb)

	// The analyzed batch contained exactly one event, from 203.0.113.7. The
	// model's response names that IP (actionable) and one the batch never
	// contained (a poisoned or hallucinated verdict).
	verdicts := []Verdict{
		{IP: "203.0.113.7", Action: "block", Reason: "confirmed scanner", Confidence: 0.9},
		{IP: "198.51.100.66", Action: "block", Reason: "poisoned verdict", Confidence: 0.95},
	}

	// The analyzed batch contained exactly one event, from 203.0.113.7.
	batchIPs := map[string]bool{"203.0.113.7": true}

	a.applyVerdicts(verdicts, batchIPs)

	if len(mb.calls) != 1 || mb.calls[0] != "203.0.113.7" {
		t.Fatalf("FAIL: the blocker banned %v, want only the in-batch 203.0.113.7 — a verdict for an IP the analyzed batch never contained must not trigger AddAutoBan", mb.calls)
	}
}

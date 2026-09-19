package crs

import (
	"testing"
)

// Regression (round 2026-09-18): Layer.Stats() reported phase_1..phase_5 rule
// counts as if every phase evaluates, but Process iterates only
// rulesByPhase[1] and [2]. A phase-5 rule (e.g. the CRS reporting SecActions)
// was parsed, registered, counted as "phase_5: N" — and never evaluated: the
// bare key read as a live rule count to any operator or dashboard consumer.
// Never-evaluated phases are now reported as parsed-only counts
// (phase_N_parsed); the evaluated phases keep their live keys.

func TestStatsNeverEvaluatedPhasesReportedAsParsed(t *testing.T) {
	rules, err := NewParser().ParseFile(
		`SecAction "id:980145,phase:5,pass,nolog"
SecRule ARGS "@rx x" "id:930001,phase:2,deny"`)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	layer := NewLayer(&Config{Enabled: true, ParanoiaLevel: 1})
	layer.rules = rules
	layer.buildRuleMaps()

	stats := layer.Stats()

	// The evaluated phase keeps its live key.
	if stats["phase_2"] != 1 {
		t.Fatalf("phase_2 = %d, want 1", stats["phase_2"])
	}
	// Never-evaluated phases are parsed-only counts.
	if stats["phase_5_parsed"] != 1 {
		t.Fatalf("phase_5_parsed = %d, want 1", stats["phase_5_parsed"])
	}
	if _, ok := stats["phase_5"]; ok {
		t.Fatalf("bare phase_5 key present — reads as a live rule count for a phase Process never iterates")
	}
	// total/disabled semantics unchanged.
	if stats["total"] != 2 {
		t.Fatalf("total = %d, want 2", stats["total"])
	}
	if _, ok := stats["disabled"]; !ok {
		t.Fatalf("disabled key missing")
	}
}

// Both evaluated phases keep their live keys, and evaluated phases never grow
// _parsed aliases.
func TestStatsEvaluatedPhasesKeepLiveKeys(t *testing.T) {
	rules, err := NewParser().ParseFile(
		`SecRule ARGS "@rx x" "id:930001,phase:1,deny"
SecRule ARGS "@rx x" "id:930002,phase:2,deny"`)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	layer := NewLayer(&Config{Enabled: true, ParanoiaLevel: 1})
	layer.rules = rules
	layer.buildRuleMaps()

	stats := layer.Stats()
	if stats["phase_1"] != 1 || stats["phase_2"] != 1 {
		t.Fatalf("evaluated phase keys wrong: phase_1=%d phase_2=%d, want 1/1", stats["phase_1"], stats["phase_2"])
	}
	if _, ok := stats["phase_1_parsed"]; ok {
		t.Fatalf("phase_1_parsed key present — evaluated phases must keep their live keys")
	}
}

package config

// Regression: floatField's minVal guard must fail the populate loudly, not
// silently skip — the sibling intField already does (defaults_hardening_test.go).
//
// Ordering in PopulateFromNode:
//   line 432  populateWAF(...) -> populateATOProtection -> fe.floatField(...)
//   line 479  populateTaggedValue(reflect.ValueOf(cfg), node)   <- runs LAST
//
// The per-section helpers all run BEFORE the reflective yaml-tag overlay, so a
// helper that "skips" an out-of-range value does not prevent it from binding —
// the overlay re-applies the raw node value afterwards. nodeIntField's comment
// (defaults.go) documents exactly this and requires a LOUD error instead.
//
// floatField used `if f > minVal { *field = f }`, so its minVal was dead. The
// only two floatFields are the ATO impossible-travel thresholds
// (populateATOProtection: max_distance_km, max_time_hours), and
// internal/layers/ato/ato.go:330 gates on `timeDiff <= cfg.MaxTimeHours`, so a
// negative threshold silently disables impossible-travel detection while the
// config still reads enabled: true.

import "testing"

func atoTravelYAML(body string) []byte {
	return []byte("waf:\n  ato_protection:\n    impossible_travel:\n      enabled: true\n" + body)
}

func TestPopulateATOTravelRejectsNegativeMaxTimeHours(t *testing.T) {
	cfg := DefaultConfig()
	before := cfg.WAF.ATOProtection.Travel.MaxTimeHours

	node, err := Parse(atoTravelYAML("      max_time_hours: -1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if popErr := PopulateFromNode(cfg, node); popErr == nil {
		t.Fatalf("FAIL: max_time_hours: -1 was accepted — a value below minVal=0 must fail " +
			"the populate loudly. A silent skip cannot bind here because populateTaggedValue " +
			"re-applies the raw yaml-tagged value after the per-section populate, and a " +
			"negative MaxTimeHours makes ato's `timeDiff <= cfg.MaxTimeHours` always true.")
	}
	if got := cfg.WAF.ATOProtection.Travel.MaxTimeHours; got != before {
		t.Fatalf("FAIL: rejected value leaked into the config (got %v, default %v)", got, before)
	}
}

func TestPopulateATOTravelRejectsNegativeMaxDistanceKm(t *testing.T) {
	cfg := DefaultConfig()
	before := cfg.WAF.ATOProtection.Travel.MaxDistanceKm

	node, err := Parse(atoTravelYAML("      max_distance_km: -5000\n"))
	if err != nil {
		t.Fatal(err)
	}
	if popErr := PopulateFromNode(cfg, node); popErr == nil {
		t.Fatalf("FAIL: max_distance_km: -5000 was accepted — must fail the populate loudly")
	}
	if got := cfg.WAF.ATOProtection.Travel.MaxDistanceKm; got != before {
		t.Fatalf("FAIL: rejected value leaked into the config (got %v, default %v)", got, before)
	}
}

// Control: in-range values still bind — the guard must not over-reject.
func TestPopulateATOTravelAcceptsPositiveThresholds(t *testing.T) {
	cfg := DefaultConfig()

	node, err := Parse(atoTravelYAML("      max_time_hours: 12.5\n      max_distance_km: 800\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("FAIL: positive thresholds must load cleanly, got %v", err)
	}
	if cfg.WAF.ATOProtection.Travel.MaxTimeHours != 12.5 {
		t.Fatalf("FAIL: max_time_hours = %v, want 12.5", cfg.WAF.ATOProtection.Travel.MaxTimeHours)
	}
	if cfg.WAF.ATOProtection.Travel.MaxDistanceKm != 800 {
		t.Fatalf("FAIL: max_distance_km = %v, want 800", cfg.WAF.ATOProtection.Travel.MaxDistanceKm)
	}
}

// Control: a zero (at minVal, inclusive) is accepted rather than rejected.
func TestPopulateATOTravelAcceptsZeroAtMinimum(t *testing.T) {
	cfg := DefaultConfig()

	node, err := Parse(atoTravelYAML("      max_time_hours: 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("FAIL: minVal is an INCLUSIVE minimum — 0 must be accepted, got %v", err)
	}
}

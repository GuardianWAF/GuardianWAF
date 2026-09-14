package config

import (
	"testing"
)

// Regression (the catalog-closure weak note): nodeIntField accepted its
// minVal parameter but never enforced it — a negative threshold or a zero
// PoW difficulty was stored as-is. minVal is now an INCLUSIVE minimum:
// values below it keep the existing default (the same malformed-value
// semantics as the parse-error path, which keeps defaults instead of
// failing the whole load).

func TestPopulateChallengeDifficultyEnforcesMinimum(t *testing.T) {
	cfg := DefaultConfig()
	node, err := Parse([]byte("waf:\n  challenge:\n    enabled: true\n    difficulty: 0"))
	if err != nil {
		t.Fatal(err)
	}
	if err := PopulateFromNode(cfg, node); err == nil {
		t.Fatalf("FAIL: difficulty 0 was accepted — values below minVal must fail the populate loudly (the reflective overlay would otherwise re-apply the raw value)")
	}
	if cfg.WAF.Challenge.Difficulty != 20 {
		t.Fatalf("FAIL: the rejected value leaked into the config (%d), want the default 20", cfg.WAF.Challenge.Difficulty)
	}
}

// Control: an exactly-at-minimum value must still be set.
func TestPopulateChallengeDifficultyAtMinimumIsRespected(t *testing.T) {
	cfg := DefaultConfig()
	node, err := Parse([]byte("waf:\n  challenge:\n    difficulty: 1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatal(err)
	}
	if cfg.WAF.Challenge.Difficulty != 1 {
		t.Fatalf("FAIL: difficulty 1 (at minVal) was not set, got %d", cfg.WAF.Challenge.Difficulty)
	}
}

func TestPopulateDetectionThresholdRejectsNegative(t *testing.T) {
	cfg := DefaultConfig()
	node, err := Parse([]byte("waf:\n  detection:\n    threshold:\n      block: -5"))
	if err != nil {
		t.Fatal(err)
	}
	if err := PopulateFromNode(cfg, node); err == nil {
		t.Fatalf("FAIL: negative threshold accepted — must fail the populate loudly")
	}
	if cfg.WAF.Detection.Threshold.Block != 50 {
		t.Fatalf("FAIL: the rejected value leaked into the config (%d), want the default 50", cfg.WAF.Detection.Threshold.Block)
	}
}

// Regression (the catalog-closure weak note): the admin dashboard shipped
// enabled on :9443 (all interfaces) with TLS:false — and dashboard.tls is
// REJECTED by the validator ("terminate TLS at an ingress"), so the listen
// address is the only posture control. The default must be loopback:
// the operator gets a working local admin UI, and remote exposure is an
// explicit dashboard.listen decision.
func TestDefaultDashboardListenIsLoopback(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Dashboard.Listen != "127.0.0.1:9443" {
		t.Fatalf("FAIL: dashboard default listen is %q, want 127.0.0.1:9443 — the admin UI has no built-in TLS and must not bind all interfaces by default", cfg.Dashboard.Listen)
	}
}

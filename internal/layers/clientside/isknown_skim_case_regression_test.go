package clientside

// Regression (round 2026-09-24-r24-ledger-cleanup): the SkimmingPatterns
// regexes match case-insensitively ((?i)), but isKnownSkimmingDomain's
// escalation check was case-SENSITIVE — a known domain embedded with mixed
// case scored as unknown-suspicious (medium) instead of known-skimmer
// (critical) in monitor mode. The escalation now lowercases both sides,
// mirroring the pattern matching.

import "testing"

func TestIsKnownSkimmingDomainCaseInsensitive(t *testing.T) {
	l := NewLayer(DefaultConfig())
	l.patterns.KnownSkimmingDomains["evil-skim.example"] = true

	if !l.isKnownSkimmingDomain(`var s="https://EVIL-SKIM.example/payload.js"`) {
		t.Fatal("FAIL: mixed-case known domain not escalated (case-sensitive check)")
	}
	if l.isKnownSkimmingDomain(`var s="https://benign-cdn.example/lib.js"`) {
		t.Fatal("FAIL: unrelated domain falsely escalated")
	}
}

package clientside

import "testing"

// GetSkimmingDomains backs the dashboard's skimming-domains list endpoint
// (clientSideAdapter.GetBlockedDomains): it must observe exactly the state
// AddSkimmingDomain writes and the config loads, return a sorted
// deterministic copy, and never leak the internal map.
func TestGetSkimmingDomainsCopyAndContent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MagecartDetection.KnownSkimmingDomains = []string{"b.example", "a.example"}
	l := NewLayer(cfg)

	got := l.GetSkimmingDomains()
	if len(got) != 2 || got[0] != "a.example" || got[1] != "b.example" {
		t.Fatalf("FAIL: got %v, want sorted [a.example b.example]", got)
	}

	// Mutating the returned slice must not affect layer state.
	got[0] = "mutated.example"
	if again := l.GetSkimmingDomains(); len(again) != 2 || again[0] != "a.example" {
		t.Fatalf("FAIL: getter leaked internal state: %v", again)
	}

	// Runtime-added domains become visible, still sorted.
	l.AddSkimmingDomain("c.example")
	got3 := l.GetSkimmingDomains()
	if len(got3) != 3 || got3[0] != "a.example" || got3[1] != "b.example" || got3[2] != "c.example" {
		t.Fatalf("FAIL: after AddSkimmingDomain got %v, want [a.example b.example c.example]", got3)
	}
}

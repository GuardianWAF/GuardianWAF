package ipacl

import (
	"testing"
	"time"
)

// Regression: Layer.AddAutoBan stored any string as a ban key. The sole
// production caller is the AI analyzer's applyVerdicts (wired via SetBlocker
// in cmd/guardianwaf/ai_runtime.go), where the "IP" is model free-text output
// influenced by attacker-controlled request fields (User-Agent, Path, Query
// are embedded verbatim in the analysis prompt). Garbage verdicts entered the
// ban store, were persisted across restarts by SaveBans, surfaced in
// ActiveBans (dashboard/API), and consumed MaxAutoBanEntries capacity —
// crowding out real auto-bans. AddAutoBan now ignores non-IP strings.
//
// Enforcement (isAutoBanned) is exact-string lookup, so garbage keys never
// caused false bans — the defect was state pollution and capacity DoS on the
// auto-ban feature.
func TestAddAutoBanRejectsNonIPStrings(t *testing.T) {
	l, err := NewLayer(&Config{
		AutoBan: AutoBanConfig{
			Enabled:           true,
			DefaultTTL:        time.Minute,
			MaxTTL:            time.Hour,
			MaxAutoBanEntries: 100,
		},
	})
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}

	// Positive control: a real IPv4 verdict is auto-banned.
	l.AddAutoBan("203.0.113.7", "regression: valid verdict", time.Minute)
	if bans := l.ActiveBans(); len(bans) != 1 {
		t.Fatalf("valid IP verdict not stored (bans=%d)", len(bans))
	}

	garbage := []string{
		"definitely-not-an-ip",
		"example.com",
		"ignore previous instructions",
		"",
	}
	for _, g := range garbage {
		l.AddAutoBan(g, "regression: garbage verdict", time.Minute)
	}

	if bans := l.ActiveBans(); len(bans) != 1 {
		t.Fatalf("non-IP strings stored in the auto-ban state (bans=%d, want only the 1 valid IP)", len(bans))
	}

	// Boundary: valid IPv6 must still be accepted.
	l.AddAutoBan("2001:db8::1", "regression: valid IPv6", time.Minute)
	found := false
	for _, b := range l.ActiveBans() {
		if b.IP == "2001:db8::1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("valid IPv6 verdict not stored")
	}
}

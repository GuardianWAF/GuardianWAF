package layerregistry

// Regression (hunt round 14, 2026-10-02): a non-positive
// waf.ip_acl.auto_ban.default_ttl silently disabled the auto-ban control.
//
// waf.ip_acl.auto_ban.default_ttl was the ONLY bound in validateIPACL that was
// never validated — validateIPACL checked the whitelist/blacklist CIDR lists
// and nothing else. With default_ttl: 0s the config loaded and validated
// clean, the rate-limit auto-ban hook (buildRateLimit's OnAutoBan closure)
// passed ttl=0 straight into ipacl.AddAutoBan, and AddAutoBan stored the entry
// with ExpiresAt == time.Now().Add(0) == now. isAutoBanned's
// time.Now().Before(entry.ExpiresAt) is therefore false forever: the ban was
// recorded, consumed one of MaxAutoBanEntries' slots, was filtered out of the
// dashboard's ActiveBans() view, and blocked nothing.
//
// Every comparable bound in the repo already guarded this: validateAIAnalysis
// rejects waf.ai_analysis.auto_block_ttl < 0, the AI analyzer self-defaults
// AutoBlockTTL<=0 to an hour (analyzer.go), and the dashboard rejects a
// non-positive ban duration outright.
//
// The fix is at both layers: validateIPACL now rejects a non-positive
// default_ttl, and AddAutoBan falls back to the configured default (then the
// shipped default) so no caller — config, library, MCP, or dashboard — can
// produce a ban that does not exist.

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/ipacl"
)

// loadAutoBanConfig builds a config with one explicit auto_ban duration line.
func loadAutoBanConfig(t *testing.T, durationLine string) *config.Config {
	t.Helper()
	cfg := config.DefaultConfig()
	node, err := config.Parse([]byte(
		"waf:\n" +
			"  ip_acl:\n" +
			"    enabled: true\n" +
			"    auto_ban:\n" +
			"      enabled: true\n" +
			durationLine))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := config.PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate: %v", err)
	}
	return cfg
}

func newAutoBanLayer(t *testing.T, defaultTTL, maxTTL time.Duration) *ipacl.Layer {
	t.Helper()
	l, err := ipacl.NewLayer(&ipacl.Config{Enabled: true, AutoBan: ipacl.AutoBanConfig{
		Enabled: true, DefaultTTL: defaultTTL, MaxTTL: maxTTL,
	}})
	if err != nil {
		t.Fatalf("ipacl.NewLayer: %v", err)
	}
	return l
}

// blockedByIP asserts through the layer's real Process() path — the only
// production enforcement point for an auto-ban.
func blockedByIP(l *ipacl.Layer, ip string) bool {
	return l.Process(&engine.RequestContext{ClientIP: net.ParseIP(ip)}).Action == engine.ActionBlock
}

// A zero default_ttl must fail validation instead of loading into an inert control.
func TestIPACLAutoBanZeroDefaultTTLIsRejected(t *testing.T) {
	cfg := loadAutoBanConfig(t, "      default_ttl: 0s\n")

	err := config.Validate(cfg)
	if err == nil {
		t.Fatalf("FAIL: waf.ip_acl.auto_ban.default_ttl: 0s validated clean — the rate-limit " +
			"auto-ban hook passes ttl=0 to ipacl.AddAutoBan, which stores an already-expired " +
			"ban that is recorded, consumes a MaxAutoBanEntries slot, is hidden from the " +
			"dashboard, and never blocks a request")
	}
	if want := "waf.ip_acl.auto_ban.default_ttl"; !strings.Contains(err.Error(), want) {
		t.Fatalf("validation error = %q, want it to mention %q", err.Error(), want)
	}
}

// A negative default_ttl is the same defect and must be rejected too.
func TestIPACLAutoBanNegativeDefaultTTLIsRejected(t *testing.T) {
	cfg := loadAutoBanConfig(t, "      default_ttl: -1h\n")
	if err := config.Validate(cfg); err == nil {
		t.Fatal("FAIL: a negative auto_ban.default_ttl validated clean — it produces a ban " +
			"expired before it is created")
	}
}

// The enforcement boundary itself: AddAutoBan must never produce an inert ban.
func TestIPACLAutoBanNeverStoresAnInertBan(t *testing.T) {
	for _, tc := range []struct {
		name       string
		defaultTTL time.Duration
		passTTL    time.Duration
	}{
		{"zero ttl with zero default", 0, 0},
		{"zero ttl with positive default", time.Hour, 0},
		{"negative ttl", time.Hour, -time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newAutoBanLayer(t, tc.defaultTTL, 24*time.Hour)
			l.AddAutoBan("203.0.113.7", "regression", tc.passTTL)

			if !blockedByIP(l, "203.0.113.7") {
				t.Fatalf("FAIL: AddAutoBan(ttl=%v) with default_ttl=%v stored a ban that never "+
					"blocks — it is recorded, counts against MaxAutoBanEntries and is hidden "+
					"from the dashboard", tc.passTTL, tc.defaultTTL)
			}
			if got := l.ActiveBans(); len(got) != 1 {
				t.Fatalf("ActiveBans() = %d entries, want 1 (an inert ban is invisible here)", len(got))
			}
		})
	}
}

// CONTROL: a positive default_ttl must still block and be listed.
func TestIPACLAutoBanPositiveDefaultTTLEnforces(t *testing.T) {
	l := newAutoBanLayer(t, time.Hour, 24*time.Hour)
	l.AddAutoBan("203.0.113.8", "regression", time.Hour)

	if !blockedByIP(l, "203.0.113.8") {
		t.Fatal("control broken: a 1h auto-ban must block via Process()")
	}
	if got := l.ActiveBans(); len(got) != 1 {
		t.Fatalf("control broken: ActiveBans() = %d entries, want 1", len(got))
	}
}

// CONTROL: the CIDR checks in validateIPACL must survive the new check.
func TestIPACLCIDRValidationUnaffected(t *testing.T) {
	for _, field := range []string{"whitelist", "blacklist"} {
		cfg := config.DefaultConfig()
		node, err := config.Parse([]byte(
			"waf:\n  ip_acl:\n    enabled: true\n    " + field + ":\n      - 'not-an-ip'\n"))
		if err != nil {
			t.Fatalf("%s parse: %v", field, err)
		}
		if err := config.PopulateFromNode(cfg, node); err != nil {
			t.Fatalf("%s populate: %v", field, err)
		}
		if err := config.Validate(cfg); err == nil {
			t.Fatalf("control broken: an invalid %s CIDR must still fail validation", field)
		}
	}
}

// CONTROL: MaxTTL clamping must still apply.
func TestIPACLAutoBanMaxTTLStillClamps(t *testing.T) {
	l := newAutoBanLayer(t, time.Hour, time.Hour)
	l.AddAutoBan("203.0.113.10", "regression", 72*time.Hour)

	got := l.ActiveBans()
	if len(got) != 1 {
		t.Fatalf("control broken: ActiveBans() = %d entries, want 1", len(got))
	}
	if d := time.Until(got[0].ExpiresAt); d > 2*time.Hour {
		t.Fatalf("control broken: MaxTTL clamp not applied, ban expires in %v", d)
	}
}

package ipacl

import (
	"net"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestRadixTree_Entries_BareIPv4(t *testing.T) {
	rt := NewRadixTree()
	if err := rt.Insert("192.168.1.1", "block"); err != nil {
		t.Fatal(err)
	}
	entries := rt.Entries()
	if len(entries) != 1 || entries[0] != "192.168.1.1" {
		t.Errorf("expected ['192.168.1.1'], got %v", entries)
	}
}

func TestIsIPv4Mapped_ShortIP(t *testing.T) {
	shortIP := net.ParseIP("1.2.3.4").To4() // 4-byte IPv4
	if isIPv4Mapped(shortIP) {
		t.Error("expected false for 4-byte IP")
	}
}

func TestRadixTree_Entries_IPv6CIDR(t *testing.T) {
	rt := NewRadixTree()
	if err := rt.Insert("2001:db8::/32", "block"); err != nil {
		t.Fatal(err)
	}
	entries := rt.Entries()
	if len(entries) != 1 || entries[0] != "2001:db8::/32" {
		t.Errorf("expected ['2001:db8::/32'], got %v", entries)
	}
}

func TestIPACL_ActiveBans(t *testing.T) {
	cfg := Config{
		Enabled: true,
		AutoBan: AutoBanConfig{Enabled: true},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	layer.AddAutoBan("1.1.1.1", "reason1", 1*time.Hour)
	layer.AddAutoBan("2.2.2.2", "reason2", 1*time.Hour)

	bans := layer.ActiveBans()
	if len(bans) != 2 {
		t.Fatalf("expected 2 active bans, got %d", len(bans))
	}

	// Verify fields
	found := false
	for _, b := range bans {
		if b.IP == "1.1.1.1" {
			found = true
			if b.Reason != "reason1" {
				t.Errorf("expected reason1, got %q", b.Reason)
			}
			if b.Count != 1 {
				t.Errorf("expected count 1, got %d", b.Count)
			}
			if b.ExpiresAt.IsZero() {
				t.Error("expected non-zero expiry")
			}
		}
	}
	if !found {
		t.Error("expected to find 1.1.1.1 in active bans")
	}
}

func TestIPACL_ActiveBans_Expired(t *testing.T) {
	cfg := Config{
		Enabled: true,
		AutoBan: AutoBanConfig{Enabled: true},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	layer.AddAutoBan("1.1.1.1", "test", 1*time.Millisecond)
	layer.AddAutoBan("2.2.2.2", "test", 1*time.Hour)

	time.Sleep(5 * time.Millisecond)

	bans := layer.ActiveBans()
	if len(bans) != 1 {
		t.Errorf("expected 1 active ban (the non-expired one), got %d", len(bans))
	}
	if len(bans) > 0 && bans[0].IP != "2.2.2.2" {
		t.Errorf("expected 2.2.2.2, got %s", bans[0].IP)
	}
}

func TestIPACL_ActiveBansAny(t *testing.T) {
	cfg := Config{
		Enabled: true,
		AutoBan: AutoBanConfig{Enabled: true},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	layer.AddAutoBan("3.3.3.3", "test", 1*time.Hour)

	result := layer.ActiveBansAny()
	bans, ok := result.([]BanEntry)
	if !ok {
		t.Fatalf("expected []BanEntry, got %T", result)
	}
	if len(bans) != 1 {
		t.Errorf("expected 1, got %d", len(bans))
	}
}

func TestIPACL_RuntimeWhitelistManagement(t *testing.T) {
	cfg := Config{Enabled: true}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Initially empty
	if entries := layer.WhitelistEntries(); len(entries) != 0 {
		t.Errorf("expected empty whitelist, got %d", len(entries))
	}

	// Add
	if err := layer.AddWhitelist("10.0.0.0/8"); err != nil {
		t.Fatalf("AddWhitelist: %v", err)
	}
	if entries := layer.WhitelistEntries(); len(entries) != 1 {
		t.Errorf("expected 1, got %d", len(entries))
	}

	// Verify it works
	ctx := makeContext("10.0.0.1")
	defer engine.ReleaseContext(ctx)
	if result := layer.Process(ctx); result.Action != engine.ActionPass {
		t.Error("expected whitelisted IP to pass")
	}

	// Remove
	if err := layer.RemoveWhitelist("10.0.0.0/8"); err != nil {
		t.Fatalf("RemoveWhitelist: %v", err)
	}
	if entries := layer.WhitelistEntries(); len(entries) != 0 {
		t.Errorf("expected empty after remove, got %d", len(entries))
	}
}

func TestIPACL_RuntimeBlacklistManagement(t *testing.T) {
	cfg := Config{Enabled: true}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Initially empty
	if entries := layer.BlacklistEntries(); len(entries) != 0 {
		t.Errorf("expected empty blacklist, got %d", len(entries))
	}

	// Add
	if err := layer.AddBlacklist("192.168.0.0/16"); err != nil {
		t.Fatalf("AddBlacklist: %v", err)
	}
	if entries := layer.BlacklistEntries(); len(entries) != 1 {
		t.Errorf("expected 1, got %d", len(entries))
	}

	// Verify it works
	ctx := makeContext("192.168.1.1")
	defer engine.ReleaseContext(ctx)
	if result := layer.Process(ctx); result.Action != engine.ActionBlock {
		t.Error("expected blacklisted IP to be blocked")
	}

	// Remove
	if err := layer.RemoveBlacklist("192.168.0.0/16"); err != nil {
		t.Fatalf("RemoveBlacklist: %v", err)
	}
	if entries := layer.BlacklistEntries(); len(entries) != 0 {
		t.Errorf("expected empty after remove, got %d", len(entries))
	}
}

func TestIPACL_AddSingleIP(t *testing.T) {
	cfg := Config{Enabled: true}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Add single IP (not CIDR)
	if err := layer.AddBlacklist("1.2.3.4"); err != nil {
		t.Fatalf("AddBlacklist single IP: %v", err)
	}

	ctx := makeContext("1.2.3.4")
	defer engine.ReleaseContext(ctx)
	if result := layer.Process(ctx); result.Action != engine.ActionBlock {
		t.Error("expected single IP to be blocked")
	}

	// Different IP should pass
	ctx2 := makeContext("1.2.3.5")
	defer engine.ReleaseContext(ctx2)
	if result := layer.Process(ctx2); result.Action != engine.ActionPass {
		t.Error("expected different IP to pass")
	}
}

func TestIPACL_MultipleCIDRs(t *testing.T) {
	cfg := Config{
		Enabled:   true,
		Blacklist: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		ip     string
		action engine.Action
	}{
		{"10.1.2.3", engine.ActionBlock},
		{"172.16.5.5", engine.ActionBlock},
		{"192.168.100.1", engine.ActionBlock},
		{"8.8.8.8", engine.ActionPass},
		{"1.1.1.1", engine.ActionPass},
	}

	for _, tt := range tests {
		ctx := makeContext(tt.ip)
		result := layer.Process(ctx)
		engine.ReleaseContext(ctx)
		if result.Action != tt.action {
			t.Errorf("IP %s: expected %v, got %v", tt.ip, tt.action, result.Action)
		}
	}
}

func TestIPACL_FindingsFields(t *testing.T) {
	cfg := Config{
		Enabled:   true,
		Blacklist: []string{"1.2.3.4"},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := makeContext("1.2.3.4")
	defer engine.ReleaseContext(ctx)
	result := layer.Process(ctx)

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.DetectorName != "ipacl" {
		t.Errorf("expected 'ipacl', got %q", f.DetectorName)
	}
	if f.Category != "ipacl" {
		t.Errorf("expected 'ipacl', got %q", f.Category)
	}
	if f.Score != 100 {
		t.Errorf("expected score 100, got %d", f.Score)
	}
	if f.Severity != engine.SeverityCritical {
		t.Errorf("expected critical severity, got %v", f.Severity)
	}
	if f.MatchedValue != "1.2.3.4" {
		t.Errorf("expected '1.2.3.4', got %q", f.MatchedValue)
	}
}

func TestIPACL_AutoBanFindingsFields(t *testing.T) {
	cfg := Config{
		Enabled: true,
		AutoBan: AutoBanConfig{Enabled: true},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	layer.AddAutoBan("5.5.5.5", "attack", 1*time.Hour)

	ctx := makeContext("5.5.5.5")
	defer engine.ReleaseContext(ctx)
	result := layer.Process(ctx)

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Description != "IP is auto-banned" {
		t.Errorf("unexpected description: %s", result.Findings[0].Description)
	}
	if result.Score != 100 {
		t.Errorf("expected score 100, got %d", result.Score)
	}
}

func TestIPACL_IPv6Whitelist(t *testing.T) {
	cfg := Config{
		Enabled:   true,
		Whitelist: []string{"::1"},
		Blacklist: []string{"::1"},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("::1"),
		Headers:  map[string][]string{},
		Cookies:  map[string]string{},
	}

	result := layer.Process(ctx)
	// Whitelist should take priority
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass (whitelist priority), got %v", result.Action)
	}
}

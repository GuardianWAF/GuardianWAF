package ipacl

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// helper to create a RequestContext with a given IP
func makeContext(ip string) *engine.RequestContext {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = ip + ":12345"
	ctx := engine.AcquireContext(req, 2, 1024)
	return ctx
}

func TestIPACL_WhitelistBypass(t *testing.T) {
	cfg := Config{
		Enabled:   true,
		Whitelist: []string{"10.0.0.1"},
		Blacklist: []string{"10.0.0.1"}, // also blacklisted — whitelist should win
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := makeContext("10.0.0.1")
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Fatalf("expected pass (whitelist bypass), got %v", result.Action)
	}
}

func TestIPACL_BlacklistBlock(t *testing.T) {
	cfg := Config{
		Enabled:   true,
		Blacklist: []string{"192.168.1.0/24"},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := makeContext("192.168.1.50")
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Fatalf("expected block, got %v", result.Action)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Description != "IP is blacklisted" {
		t.Fatalf("unexpected description: %s", result.Findings[0].Description)
	}
}

func TestIPACL_NotBlacklisted(t *testing.T) {
	cfg := Config{
		Enabled:   true,
		Blacklist: []string{"192.168.1.0/24"},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := makeContext("10.0.0.1")
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Fatalf("expected pass, got %v", result.Action)
	}
}

func TestIPACL_WhitelistPriorityOverBlacklist(t *testing.T) {
	cfg := Config{
		Enabled:   true,
		Whitelist: []string{"10.0.0.0/8"},
		Blacklist: []string{"10.0.0.0/8"},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := makeContext("10.5.5.5")
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Fatalf("expected pass (whitelist priority), got %v", result.Action)
	}
}

func TestIPACL_AutoBanAddAndCheck(t *testing.T) {
	cfg := Config{
		Enabled: true,
		AutoBan: AutoBanConfig{
			Enabled:    true,
			DefaultTTL: 5 * time.Minute,
		},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	ip := "172.16.0.100"
	layer.AddAutoBan(ip, "testing", 1*time.Minute)

	ctx := makeContext(ip)
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Fatalf("expected block (auto-banned), got %v", result.Action)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Description != "IP is auto-banned" {
		t.Fatalf("unexpected description: %s", result.Findings[0].Description)
	}
}

func TestIPACL_AutoBanRemove(t *testing.T) {
	cfg := Config{
		Enabled: true,
		AutoBan: AutoBanConfig{Enabled: true},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	ip := "172.16.0.101"
	layer.AddAutoBan(ip, "testing", 1*time.Minute)
	layer.RemoveAutoBan(ip)

	ctx := makeContext(ip)
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Fatalf("expected pass (removed auto-ban), got %v", result.Action)
	}
}

func TestIPACL_AutoBanExpiry(t *testing.T) {
	cfg := Config{
		Enabled: true,
		AutoBan: AutoBanConfig{Enabled: true},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	ip := "172.16.0.102"
	// Add with very short TTL
	layer.AddAutoBan(ip, "testing", 1*time.Millisecond)

	// Wait for expiry
	time.Sleep(5 * time.Millisecond)

	ctx := makeContext(ip)
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Fatalf("expected pass (expired auto-ban), got %v", result.Action)
	}
}

func TestIPACL_CleanupExpired(t *testing.T) {
	cfg := Config{
		Enabled: true,
		AutoBan: AutoBanConfig{Enabled: true},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	layer.AddAutoBan("1.1.1.1", "test1", 1*time.Millisecond)
	layer.AddAutoBan("2.2.2.2", "test2", 1*time.Hour)

	time.Sleep(5 * time.Millisecond)
	layer.CleanupExpired()

	layer.mu.RLock()
	_, exists1 := layer.autoBan["1.1.1.1"]
	_, exists2 := layer.autoBan["2.2.2.2"]
	layer.mu.RUnlock()

	if exists1 {
		t.Fatal("expected 1.1.1.1 to be cleaned up")
	}
	if !exists2 {
		t.Fatal("expected 2.2.2.2 to still exist")
	}
}

func TestIPACL_AutoBanMaxTTL(t *testing.T) {
	cfg := Config{
		Enabled: true,
		AutoBan: AutoBanConfig{
			Enabled: true,
			MaxTTL:  10 * time.Second,
		},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Request TTL longer than MaxTTL
	layer.AddAutoBan("5.5.5.5", "test", 1*time.Hour)

	layer.mu.RLock()
	entry := layer.autoBan["5.5.5.5"]
	layer.mu.RUnlock()

	// The expiry should be roughly now + MaxTTL, not now + 1 hour
	expiresAt, _ := entry.ExpiresAt.Load().(time.Time)
	remaining := time.Until(expiresAt)
	if remaining > 15*time.Second {
		t.Fatalf("expected TTL capped to ~10s, got %v", remaining)
	}
}

func TestIPACL_DisabledLayer(t *testing.T) {
	cfg := Config{
		Enabled:   false,
		Blacklist: []string{"0.0.0.0/0"}, // blacklist everything
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := makeContext("1.2.3.4")
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Fatalf("expected pass (disabled layer), got %v", result.Action)
	}
}

func TestIPACL_NilClientIP(t *testing.T) {
	cfg := Config{
		Enabled:   true,
		Blacklist: []string{"0.0.0.0/0"},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Create context with nil IP
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = ""
	ctx := engine.AcquireContext(req, 2, 1024)
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Fatalf("expected pass (nil IP), got %v", result.Action)
	}
}

func TestIPACL_ConcurrentAutoBan(t *testing.T) {
	cfg := Config{
		Enabled: true,
		AutoBan: AutoBanConfig{Enabled: true},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	const goroutines = 50

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := net.IPv4(10, 0, byte(id/256), byte(id%256)).String()
			layer.AddAutoBan(ip, "concurrent test", 1*time.Minute)

			ctx := makeContext(ip)
			layer.Process(ctx)
			engine.ReleaseContext(ctx)

			layer.RemoveAutoBan(ip)
		}(g)
	}

	wg.Wait()
}

func TestIPACL_WhitelistedIPSkipsAutoBan(t *testing.T) {
	cfg := Config{
		Enabled:   true,
		Whitelist: []string{"10.0.0.1"},
		AutoBan:   AutoBanConfig{Enabled: true},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Auto-ban the whitelisted IP
	layer.AddAutoBan("10.0.0.1", "test", 1*time.Hour)

	ctx := makeContext("10.0.0.1")
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Fatalf("expected pass (whitelist overrides auto-ban), got %v", result.Action)
	}
}

func TestIPACL_Name(t *testing.T) {
	layer, _ := NewLayer(&Config{})
	if layer.Name() != "ipacl" {
		t.Fatalf("expected name 'ipacl', got %q", layer.Name())
	}
}

func TestIPACL_InvalidConfig(t *testing.T) {
	cfg := Config{
		Enabled:   true,
		Blacklist: []string{"not-valid-cidr-at-all!!!"},
	}
	_, err := NewLayer(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid blacklist entry")
	}
}

func TestIPACL_AutoBanIncrementCount(t *testing.T) {
	cfg := Config{
		Enabled: true,
		AutoBan: AutoBanConfig{Enabled: true},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	ip := "8.8.8.8"
	layer.AddAutoBan(ip, "first", 1*time.Minute)
	layer.AddAutoBan(ip, "second", 1*time.Minute)

	layer.mu.RLock()
	entry := layer.autoBan[ip]
	count := entry.Count
	reason := entry.Reason
	layer.mu.RUnlock()

	if count != 2 {
		t.Fatalf("expected count 2, got %d", count)
	}
	if reason != "second" {
		t.Fatalf("expected reason 'second', got %q", reason)
	}
}

func TestIPACL_InvalidWhitelistConfig(t *testing.T) {
	cfg := Config{
		Enabled:   true,
		Whitelist: []string{"totally-invalid-ip!!!"},
	}
	_, err := NewLayer(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid whitelist entry")
	}
}

func TestIPACL_AutoBanMaxTTL_NoCap(t *testing.T) {
	// When MaxTTL is 0, no capping should occur
	cfg := Config{
		Enabled: true,
		AutoBan: AutoBanConfig{
			Enabled: true,
			MaxTTL:  0,
		},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	layer.AddAutoBan("9.9.9.9", "test", 1*time.Hour)

	layer.mu.RLock()
	entry := layer.autoBan["9.9.9.9"]
	layer.mu.RUnlock()

	expiresAt, _ := entry.ExpiresAt.Load().(time.Time)
	remaining := time.Until(expiresAt)
	if remaining < 55*time.Minute {
		t.Fatalf("expected TTL near 1 hour (no cap), got %v", remaining)
	}
}

func TestIPACL_RemoveAutoBan_NonExistent(t *testing.T) {
	cfg := Config{
		Enabled: true,
		AutoBan: AutoBanConfig{Enabled: true},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Should not panic when removing non-existent entry
	layer.RemoveAutoBan("99.99.99.99")

	layer.mu.RLock()
	_, exists := layer.autoBan["99.99.99.99"]
	layer.mu.RUnlock()

	if exists {
		t.Fatal("entry should not exist after removing non-existent IP")
	}
}

func TestIPACL_IPv6Blacklist(t *testing.T) {
	cfg := Config{
		Enabled:   true,
		Blacklist: []string{"2001:db8::/32"},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("2001:db8::1"),
		Headers:  map[string][]string{},
		Cookies:  map[string]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Fatalf("expected block for IPv6 in blacklist, got %v", result.Action)
	}
}

func TestIPACL_ConcurrentAddRemoveCleanup(t *testing.T) {
	cfg := Config{
		Enabled: true,
		AutoBan: AutoBanConfig{Enabled: true},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := net.IPv4(10, 0, byte(id/256), byte(id%256)).String()
			layer.AddAutoBan(ip, "test", 1*time.Millisecond)
			time.Sleep(2 * time.Millisecond)
			layer.CleanupExpired()
			layer.RemoveAutoBan(ip)
		}(i)
	}
	wg.Wait()
}

func TestParseCIDROrIP_InvalidIP(t *testing.T) {
	// An IP that is neither a valid CIDR nor a valid bare IP
	_, err := NewLayer(&Config{
		Enabled:   true,
		Blacklist: []string{"not-an-ip"},
	})
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestParseCIDROrIP_IPv6Bare(t *testing.T) {
	// Bare IPv6 address (no CIDR)
	layer, err := NewLayer(&Config{
		Enabled:   true,
		Blacklist: []string{"::1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Verify by processing a request from ::1
	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("::1"),
		Metadata: make(map[string]any),
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Error("expected ::1 to be blocked")
	}
}

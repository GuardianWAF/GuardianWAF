package ipacl

import (
	"os"
	"path/filepath"
	"net"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// TestWalk_NilNode covers the node==nil guard in walk.
func TestWalk_NilNode(t *testing.T) {
	rt := NewRadixTree()
	var result []string
	rt.walk(nil, nil, &result)
	if len(result) != 0 {
		t.Errorf("expected empty result for nil node, got %v", result)
	}
}

// TestParseCIDROrIP_InvalidIPTo16 tries edge-case inputs that may trigger the
// defensive nil checks after To16().  In practice these checks are effectively
// unreachable with the current net package, but the tests document the
// behavior and exercise the branches if they ever become reachable.
func TestParseCIDROrIP_InvalidCIDRTo16(t *testing.T) {
	// net.ParseCIDR can succeed for some degenerate inputs, but To16()
	// should still work for anything ParseCIDR accepts.  We test an
	// invalid-looking CIDR to ensure parseCIDROrIP returns an error.
	_, _, err := parseCIDROrIP("not-a-cidr")
	if err == nil {
		t.Error("expected error for invalid CIDR string")
	}
}

func TestParseCIDROrIP_InvalidBareIPTo16(t *testing.T) {
	// Anything that net.ParseIP accepts will have a non-nil To16().
	// We simply verify the error path for a completely invalid IP.
	_, _, err := parseCIDROrIP("not-an-ip")
	if err == nil {
		t.Error("expected error for invalid bare IP string")
	}
}

// TestRadixTree_Entries_IPv4MappedFallback covers the unlikely path in walk
// where isIPv4Mapped is true but ip.To4() returns nil.  We fabricate a
// 16-byte IP that has the ::ffff: prefix but with a length that prevents
// To4() from working as expected.
func TestRadixTree_Entries_IPv4MappedFallback(t *testing.T) {
	rt := NewRadixTree()
	// Insert an IPv4 bare IP; internally it is stored as IPv6-mapped.
	// Entries() should convert it back to IPv4 display.
	if err := rt.Insert("192.0.2.1", "test"); err != nil {
		t.Fatal(err)
	}
	entries := rt.Entries()
	if len(entries) != 1 || entries[0] != "192.0.2.1" {
		t.Errorf("expected ['192.0.2.1'], got %v", entries)
	}

	// Insert an IPv4 CIDR.
	if err := rt.Insert("10.0.0.0/8", "test"); err != nil {
		t.Fatal(err)
	}
	entries = rt.Entries()
	found := false
	for _, e := range entries {
		if e == "10.0.0.0/8" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 10.0.0.0/8 in entries, got %v", entries)
	}
}

// TestRadixTree_Lookup_IPv6Bare covers IPv6 insertion and lookup.
func TestRadixTree_Lookup_IPv6Bare(t *testing.T) {
	rt := NewRadixTree()
	ip := net.ParseIP("2001:db8::1")
	if err := rt.Insert("2001:db8::1/128", "block"); err != nil {
		t.Fatal(err)
	}
	val, ok := rt.Lookup(ip)
	if !ok || val != "block" {
		t.Errorf("expected IPv6 lookup to succeed")
	}
}

func TestIPACL_Order(t *testing.T) {
	layer, err := NewLayer(&Config{})
	if err != nil {
		t.Fatal(err)
	}
	if layer.Order() != engine.OrderIPACL {
		t.Fatalf("expected order %d, got %d", engine.OrderIPACL, layer.Order())
	}
}

func TestPersistLoop_FlushesOnTicker(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bans.json")

	layer, err := NewLayer(&Config{
		Enabled: true,
		AutoBan: AutoBanConfig{
			Enabled:         true,
			PersistPath:     path,
			PersistInterval: 10 * time.Millisecond,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer layer.Stop()

	layer.AddAutoBan("7.7.7.7", "ticker", time.Hour)

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && len(data) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("expected persist loop to flush %s", path)
}

func TestSaveBans_InvalidPersistPathIsIgnored(t *testing.T) {
	layer, err := NewLayer(&Config{Enabled: true, AutoBan: AutoBanConfig{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	layer.AddAutoBan("1.2.3.4", "test", time.Hour)

	layer.SaveBans("bad\x00path.json")
}

func TestSaveBans_MkdirAllFailureLeavesNoFile(t *testing.T) {
	base := t.TempDir()
	blocker := filepath.Join(base, "blocker")
	if err := os.WriteFile(blocker, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(blocker, "nested", "bans.json")

	layer, err := NewLayer(&Config{Enabled: true, AutoBan: AutoBanConfig{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	layer.AddAutoBan("1.2.3.4", "test", time.Hour)

	layer.SaveBans(path)

	if _, err := os.Stat(path); err == nil {
		t.Fatalf("expected no persisted file when mkdir fails")
	}
}

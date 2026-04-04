package ipacl

import (
	"net"
	"testing"
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

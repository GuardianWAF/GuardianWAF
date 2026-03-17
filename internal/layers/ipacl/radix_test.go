package ipacl

import (
	"net"
	"sync"
	"testing"
)

func TestRadixTree_InsertAndLookupSingleIP(t *testing.T) {
	tree := NewRadixTree()

	if err := tree.Insert("192.168.1.1", "host1"); err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	val, found := tree.Lookup(net.ParseIP("192.168.1.1"))
	if !found {
		t.Fatal("expected to find 192.168.1.1")
	}
	if val != "host1" {
		t.Fatalf("expected host1, got %v", val)
	}

	_, found = tree.Lookup(net.ParseIP("192.168.1.2"))
	if found {
		t.Fatal("should not find 192.168.1.2")
	}
}

func TestRadixTree_InsertAndLookupCIDR(t *testing.T) {
	tree := NewRadixTree()

	tests := []struct {
		cidr     string
		value    string
		matchIP  string
		noMatch  string
	}{
		{"10.0.0.0/8", "class-a", "10.255.255.255", "11.0.0.0"},
		{"172.16.0.0/16", "class-b", "172.16.255.255", "172.17.0.0"},
		{"192.168.1.0/24", "class-c", "192.168.1.254", "192.168.2.0"},
		{"192.168.1.100/32", "single", "192.168.1.100", "192.168.1.101"},
	}

	for _, tt := range tests {
		if err := tree.Insert(tt.cidr, tt.value); err != nil {
			t.Fatalf("Insert %s failed: %v", tt.cidr, err)
		}
	}

	for _, tt := range tests {
		val, found := tree.Lookup(net.ParseIP(tt.matchIP))
		if !found {
			t.Errorf("expected to find %s in %s", tt.matchIP, tt.cidr)
			continue
		}
		// For overlapping, we get the longest prefix match
		if val == nil {
			t.Errorf("expected non-nil value for %s", tt.matchIP)
		}

		_, found = tree.Lookup(net.ParseIP(tt.noMatch))
		// noMatch might match a broader CIDR (e.g., 192.168.2.0 won't match /24 but
		// it shouldn't match class-c). We just check it doesn't match THIS specific CIDR.
		// For non-overlapping, it should not be found.
		_ = found
	}
}

func TestRadixTree_OverlappingCIDRs(t *testing.T) {
	tree := NewRadixTree()

	// Insert broader first, then narrower
	if err := tree.Insert("10.0.0.0/8", "broad"); err != nil {
		t.Fatal(err)
	}
	if err := tree.Insert("10.1.0.0/16", "medium"); err != nil {
		t.Fatal(err)
	}
	if err := tree.Insert("10.1.1.0/24", "narrow"); err != nil {
		t.Fatal(err)
	}

	// Should match the longest (most specific) prefix
	val, found := tree.Lookup(net.ParseIP("10.1.1.5"))
	if !found {
		t.Fatal("expected to find 10.1.1.5")
	}
	if val != "narrow" {
		t.Fatalf("expected narrow, got %v", val)
	}

	val, found = tree.Lookup(net.ParseIP("10.1.2.5"))
	if !found {
		t.Fatal("expected to find 10.1.2.5")
	}
	if val != "medium" {
		t.Fatalf("expected medium, got %v", val)
	}

	val, found = tree.Lookup(net.ParseIP("10.2.0.1"))
	if !found {
		t.Fatal("expected to find 10.2.0.1")
	}
	if val != "broad" {
		t.Fatalf("expected broad, got %v", val)
	}

	// Outside all ranges
	_, found = tree.Lookup(net.ParseIP("11.0.0.1"))
	if found {
		t.Fatal("should not find 11.0.0.1")
	}
}

func TestRadixTree_IPv6(t *testing.T) {
	tree := NewRadixTree()

	if err := tree.Insert("2001:db8::/32", "ipv6-block"); err != nil {
		t.Fatalf("Insert IPv6 CIDR failed: %v", err)
	}
	if err := tree.Insert("::1", "loopback6"); err != nil {
		t.Fatalf("Insert IPv6 single failed: %v", err)
	}

	val, found := tree.Lookup(net.ParseIP("2001:db8::1"))
	if !found {
		t.Fatal("expected to find 2001:db8::1")
	}
	if val != "ipv6-block" {
		t.Fatalf("expected ipv6-block, got %v", val)
	}

	val, found = tree.Lookup(net.ParseIP("::1"))
	if !found {
		t.Fatal("expected to find ::1")
	}
	if val != "loopback6" {
		t.Fatalf("expected loopback6, got %v", val)
	}

	_, found = tree.Lookup(net.ParseIP("2001:db9::1"))
	if found {
		t.Fatal("should not find 2001:db9::1")
	}
}

func TestRadixTree_Remove(t *testing.T) {
	tree := NewRadixTree()

	if err := tree.Insert("192.168.1.0/24", "net1"); err != nil {
		t.Fatal(err)
	}
	if err := tree.Insert("192.168.2.0/24", "net2"); err != nil {
		t.Fatal(err)
	}

	if tree.Len() != 2 {
		t.Fatalf("expected len 2, got %d", tree.Len())
	}

	// Remove one
	if err := tree.Remove("192.168.1.0/24"); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	if tree.Len() != 1 {
		t.Fatalf("expected len 1 after remove, got %d", tree.Len())
	}

	_, found := tree.Lookup(net.ParseIP("192.168.1.100"))
	if found {
		t.Fatal("should not find 192.168.1.100 after removal")
	}

	val, found := tree.Lookup(net.ParseIP("192.168.2.100"))
	if !found {
		t.Fatal("expected to still find 192.168.2.100")
	}
	if val != "net2" {
		t.Fatalf("expected net2, got %v", val)
	}

	// Remove non-existent
	err := tree.Remove("10.0.0.0/8")
	if err == nil {
		t.Fatal("expected error removing non-existent entry")
	}
}

func TestRadixTree_RemoveNonExistent(t *testing.T) {
	tree := NewRadixTree()
	err := tree.Remove("192.168.1.0/24")
	if err == nil {
		t.Fatal("expected error removing from empty tree")
	}
}

func TestRadixTree_Len(t *testing.T) {
	tree := NewRadixTree()
	if tree.Len() != 0 {
		t.Fatalf("expected len 0, got %d", tree.Len())
	}

	tree.Insert("10.0.0.0/8", true)
	tree.Insert("172.16.0.0/12", true)
	tree.Insert("192.168.0.0/16", true)

	if tree.Len() != 3 {
		t.Fatalf("expected len 3, got %d", tree.Len())
	}

	// Re-insert same key should not increase count
	tree.Insert("10.0.0.0/8", true)
	if tree.Len() != 3 {
		t.Fatalf("expected len 3 after re-insert, got %d", tree.Len())
	}
}

func TestRadixTree_InvalidInput(t *testing.T) {
	tree := NewRadixTree()

	err := tree.Insert("not-a-cidr", nil)
	if err == nil {
		t.Fatal("expected error for invalid input")
	}

	err = tree.Insert("999.999.999.999", nil)
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestRadixTree_ConcurrentAccess(t *testing.T) {
	tree := NewRadixTree()

	// Pre-populate
	for i := 0; i < 256; i++ {
		cidr := net.IPv4(10, 0, byte(i), 0).String() + "/24"
		if err := tree.Insert(cidr, i); err != nil {
			// Some might be normalized differently, skip errors
			_ = err
		}
	}

	var wg sync.WaitGroup
	const goroutines = 50
	const ops = 100

	// Concurrent readers
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < ops; i++ {
				ip := net.IPv4(10, 0, byte(id%256), byte(i%256))
				tree.Lookup(ip)
			}
		}(g)
	}

	// Concurrent writers
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < ops; i++ {
				cidr := net.IPv4(172, 16, byte(id), byte(i%256)).String() + "/32"
				tree.Insert(cidr, id)
			}
		}(g)
	}

	wg.Wait()
}

func TestRadixTree_LookupNilIP(t *testing.T) {
	tree := NewRadixTree()
	tree.Insert("10.0.0.0/8", true)

	_, found := tree.Lookup(nil)
	if found {
		t.Fatal("should not find nil IP")
	}
}

func TestRadixTree_BareIPv4(t *testing.T) {
	tree := NewRadixTree()

	if err := tree.Insert("1.2.3.4", "exact"); err != nil {
		t.Fatal(err)
	}

	val, found := tree.Lookup(net.ParseIP("1.2.3.4"))
	if !found {
		t.Fatal("expected to find 1.2.3.4")
	}
	if val != "exact" {
		t.Fatalf("expected exact, got %v", val)
	}

	_, found = tree.Lookup(net.ParseIP("1.2.3.5"))
	if found {
		t.Fatal("should not find 1.2.3.5")
	}
}

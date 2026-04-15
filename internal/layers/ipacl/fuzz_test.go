package ipacl

import (
	"net"
	"testing"
)

func FuzzRadixTree(f *testing.F) {
	f.Add("192.168.1.1")
	f.Add("10.0.0.0/8")
	f.Add("172.16.0.0/12")
	f.Add("::1")
	f.Add("fe80::/10")
	f.Add("192.0.2.1/32")
	f.Add("0.0.0.0/0")
	f.Add("invalid")
	f.Add("")
	f.Add("192.168.1.256")
	f.Add("10.0.0.0/-1")
	f.Add("10.0.0.0/33")
	f.Add("192.168.1.1/24")

	f.Fuzz(func(t *testing.T, cidr string) {
		tree := NewRadixTree()

		// Insert should not panic
		_ = tree.Insert(cidr, "test")

		// Lookup with parsed IP should not panic
		if ip := net.ParseIP(cidr); ip != nil {
			_, _ = tree.Lookup(ip)
		}

		// Remove should not panic
		_ = tree.Remove(cidr)
	})
}

func FuzzRadixTreeLookup(f *testing.F) {
	tree := NewRadixTree()
	_ = tree.Insert("10.0.0.0/8", "tenant-a")
	_ = tree.Insert("192.168.1.0/24", "tenant-b")
	_ = tree.Insert("172.16.0.0/12", "tenant-c")

	f.Fuzz(func(t *testing.T, ipStr string) {
		// Lookup should not panic regardless of input
		if ip := net.ParseIP(ipStr); ip != nil {
			_, _ = tree.Lookup(ip)
		}
	})
}

func FuzzRadixTreeRemove(f *testing.F) {
	tree := NewRadixTree()
	_ = tree.Insert("10.0.0.0/8", "test")

	f.Fuzz(func(t *testing.T, cidr string) {
		// Remove should not panic
		_ = tree.Remove(cidr)

		// Len should be accessible
		_ = tree.Len()
	})
}
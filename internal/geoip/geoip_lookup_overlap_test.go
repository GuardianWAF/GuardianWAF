package geoip

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func writeGeoIPCSV(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "geoip.csv")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write csv: %v", err)
	}
	return path
}

// TestLookupNestedRanges pins overlap resolution: LoadCSV accepts nested
// ranges (e.g. a /24 carve-out inside a /16), and Lookup previously checked
// only the single last-start candidate — an IP inside the shadowed portion
// of the broader range resolved to "" instead of the broad range's country.
// Precedence: the most specific (latest-start) containing range wins.
func TestLookupNestedRanges(t *testing.T) {
	db, err := LoadCSV(writeGeoIPCSV(t, `# broad US range with DE and CN carve-outs
10.0.0.0,10.0.9.255,US
10.0.2.0,10.0.2.255,DE
10.0.3.0,10.0.3.255,CN
`))
	if err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}

	tests := []struct {
		ip   string
		want string
	}{
		{"10.0.0.0", "US"},   // broad range start boundary
		{"10.0.1.0", "US"},   // broad range, before any carve-out
		{"10.0.2.5", "DE"},   // inside DE carve-out (most specific wins)
		{"10.0.3.10", "CN"},  // inside CN carve-out (most specific wins)
		{"10.0.5.0", "US"},   // shadowed tail: only the broad range claims this
		{"10.0.9.255", "US"}, // broad range end boundary
		{"10.1.0.1", ""},     // undeclared
	}
	for _, tc := range tests {
		if got := db.Lookup(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("Lookup(%s) = %q; want %q", tc.ip, got, tc.want)
		}
	}
}

// TestLookupDisjointRangesUnchanged guards the hot path: disjoint ranges
// (official datasets) must behave exactly as before, including misses in the
// gaps between ranges.
func TestLookupDisjointRangesUnchanged(t *testing.T) {
	db, err := LoadCSV(writeGeoIPCSV(t, `10.0.0.0,10.0.0.255,US
10.0.2.0,10.0.2.255,DE
`))
	if err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}

	tests := []struct {
		ip   string
		want string
	}{
		{"10.0.0.1", "US"},
		{"10.0.0.255", "US"},
		{"10.0.1.0", ""},     // gap between ranges
		{"10.0.2.128", "DE"}, // DE end boundary inside
		{"10.0.3.0", ""},     // after the last range
	}
	for _, tc := range tests {
		if got := db.Lookup(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("Lookup(%s) = %q; want %q", tc.ip, got, tc.want)
		}
	}
}

// TestReloadPreservesOverlapResolution ensures Reload swaps the overlap
// bookkeeping alongside the ranges so post-reload lookups stay correct.
func TestReloadPreservesOverlapResolution(t *testing.T) {
	path := writeGeoIPCSV(t, "10.0.0.0,10.0.9.255,US\n10.0.3.0,10.0.3.255,CN\n")
	db, err := LoadCSV(path)
	if err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}
	if err := db.Reload(path); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := db.Lookup(net.ParseIP("10.0.5.0")); got != "US" {
		t.Errorf("Lookup after Reload = %q; want %q", got, "US")
	}
}

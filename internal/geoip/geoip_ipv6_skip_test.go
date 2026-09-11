package geoip

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// Regression (bug-hunt round 32): LoadCSV's start_ip,end_ip,country branch
// parsed endpoints with net.ParseIP (accepts IPv6) and converted them via
// ipToUint32, which returns 0 for anything non-IPv4 — unchecked. Every IPv6
// row in the CSV therefore materialized as a zero-width phantom range
// {0,0,country} at 0.0.0.0: Count() inflated, and Lookup(0.0.0.0) (target 0)
// matched the last phantom row and returned that row's arbitrary country,
// violating Lookup's documented "returns empty if not found" contract. The
// default auto-download dataset (DB-IP country lite) ships IPv6 rows, so the
// default path was affected. The CIDR branch already rejected non-IPv4 via
// cidrToRange; the simple-format branch now skips them too (To4() == nil).
//
// Lookup remains IPv4-only by design (see TestLookupIPv6): the DB simply
// must not carry phantom IPv6-derived entries.

func TestLoadCSV_SkipsIPv6Rows(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	content := `# mixed families, as real datasets ship
8.8.8.0,8.8.8.255,US
2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,XB
2001:dead::,2001:dead:ffff:ffff:ffff:ffff:ffff:ffff,ZZ
` + "\n"
	if err := os.WriteFile(csv, []byte(content), 0o644); err != nil {
		t.Fatalf("write csv: %v", err)
	}

	db, err := LoadCSV(csv)
	if err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}

	if got := db.Count(); got != 1 {
		t.Fatalf("FAIL: Count() = %d, want 1 — IPv6 rows materialized as phantom zero-width ranges at 0.0.0.0 (ipToUint32 returns 0 for non-IPv4)", got)
	}
	if got := db.Lookup(net.ParseIP("0.0.0.0")); got != "" {
		t.Fatalf("FAIL: Lookup(0.0.0.0) = %q, want \"\" — a phantom IPv6-derived range answered the unspecified address", got)
	}
	if got := db.Lookup(net.ParseIP("2001:db8::1")); got != "" {
		t.Fatalf("IPv6 lookup must stay unsupported, got %q", got)
	}
	if got := db.Lookup(net.ParseIP("8.8.8.8")); got != "US" {
		t.Fatalf("valid IPv4 range broke after skipping IPv6 rows: got %q, want US", got)
	}
}

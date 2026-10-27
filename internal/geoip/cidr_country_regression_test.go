package geoip

import (
	"net"
	"os"
	"testing"
)

func TestCIDRCountryCodeValidationMatchesOtherLayouts(t *testing.T) {
	path := writeGeoIPCSV(t, "10.0.0.0/24, us \n11.0.0.0/24,USA\n12.0.0.0/24,U\n13.0.0.0/24,\n14.0.0.0/24,de,extra\n15.0.0.0,15.0.0.255,tr\n")
	db, err := LoadCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	if db.Count() != 3 || !db.Ready() {
		t.Fatalf("count=%d", db.Count())
	}
	for ip, want := range map[string]string{"10.0.0.1": "US", "11.0.0.1": "", "12.0.0.1": "", "13.0.0.1": "", "14.0.0.1": "DE", "15.0.0.1": "TR"} {
		if got := db.Lookup(net.ParseIP(ip)); got != want {
			t.Fatalf("%s got %q want %q", ip, got, want)
		}
	}
	if err := os.WriteFile(path, []byte("10.0.0.0/24,\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := db.Reload(path); err != nil {
		t.Fatal(err)
	}
	if db.Ready() || db.Count() != 0 || db.Lookup(net.ParseIP("10.0.0.1")) != "" {
		t.Fatal("invalid-only data retained")
	}
	t.Log("FIX VERIFIED")
}

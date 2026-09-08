package ato

import (
	"net"
	"testing"
)

// Regression: LocationDB.Lookup built its /24 prefix key as
// string(ip4[:3]) + ".0/24" — the RAW BYTES converted to a string
// ("\n\x00\x00.0/24" for 10.0.0.x) — which can never match the
// human-readable CIDR keys added via Add ("10.0.0.0/24"). Every subnet
// entry was unreachable; only exact-IP entries resolved.

func TestLocationDBSubnetLookup(t *testing.T) {
	db := NewLocationDB()
	nyc := &GeoLocation{Latitude: 40.7128, Longitude: -74.006}

	db.Add("10.0.0.0/24", nyc)

	// An IP inside the /24 must resolve via the prefix fallback.
	if loc := db.Lookup(net.ParseIP("10.0.0.55")); loc != nyc {
		t.Fatalf("FAIL: /24 subnet lookup returned %v for an in-subnet IP (want the seeded location)", loc)
	}

	// An IP outside the /24 must stay unresolved.
	if loc := db.Lookup(net.ParseIP("10.0.1.55")); loc != nil {
		t.Fatalf("FAIL: out-of-subnet IP resolved: %v", loc)
	}
}

func TestLocationDBExactIP(t *testing.T) {
	db := NewLocationDB()
	nyc := &GeoLocation{Latitude: 40.7128, Longitude: -74.006}

	db.Add("10.0.0.9", nyc)

	if loc := db.Lookup(net.ParseIP("10.0.0.9")); loc != nyc {
		t.Fatalf("FAIL: exact-IP lookup returned %v (want the seeded location)", loc)
	}
}

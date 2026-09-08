package config

import "testing"

// Regression: validateTrustedProxies accepted v4-mapped IPv6 CIDRs such as
// ::ffff:0.0.0.0/96. The broadness checks (ones==0 for all, ones<8 for IPv4,
// ones<32 for IPv6) all pass for a /96 mapped range, but on dual-stack
// listeners every IPv4 client arrives as a v4-mapped address and matches
// that CIDR — trusting it is equivalent to trusting all clients, which
// enables X-Forwarded-For spoofing and bypasses every per-IP control.
func TestTrustedProxiesRejectV4MappedRange(t *testing.T) {
	ve := &ValidationError{}
	validateTrustedProxies([]string{"::ffff:0.0.0.0/96"}, ve)
	if !ve.HasErrors() {
		t.Fatalf("FAIL: v4-mapped ::ffff:0.0.0.0/96 accepted as a trusted proxy range — it matches every IPv4 client on dual-stack listeners")
	}

	// The plain forms a real operator would use stay accepted.
	ve2 := &ValidationError{}
	validateTrustedProxies([]string{"10.0.0.0/8", "2001:db8::/32", "10.0.0.9"}, ve2)
	if ve2.HasErrors() {
		t.Fatalf("FAIL: legitimate trusted proxy forms rejected: %v", ve2.Errors)
	}
}

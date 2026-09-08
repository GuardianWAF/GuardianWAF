package engine

import (
	"net/http"
	"testing"
)

// Regression: parseTrustedProxyCIDRs accepted v4-mapped IPv6 CIDRs such as
// ::ffff:0.0.0.0/96. On dual-stack listeners IPv4 clients arrive as
// v4-mapped addresses, so such an entry matched every IPv4 client and the
// X-Forwarded-For header was honored from anyone — full IP spoofing into
// every per-IP control (rate limits, IPACL, botdetect, ato).
func TestV4MappedTrustedProxyRangeRejected(t *testing.T) {
	cidrs := parseTrustedProxyCIDRs([]string{"::ffff:0.0.0.0/96"})
	if len(cidrs) != 0 {
		t.Fatalf("FAIL: v4-mapped ::ffff:0.0.0.0/96 accepted as a trusted proxy range — it matches every IPv4 client on dual-stack listeners (parsed %d entries)", len(cidrs))
	}

	// The plain forms a real operator would use stay accepted.
	plain := parseTrustedProxyCIDRs([]string{"10.0.0.0/8", "2001:db8::/32", "10.0.0.9"})
	if len(plain) != 3 {
		t.Fatalf("FAIL: legitimate trusted proxy forms rejected (parsed %d of 3)", len(plain))
	}
}

// The full spoof chain: with the mapped range trusted, a v4-mapped remote
// peer is treated as a trusted proxy and the attacker-supplied XFF is
// returned as the client IP.
func TestExtractClientIPV4MappedTrustSpoof(t *testing.T) {
	cidrs := parseTrustedProxyCIDRs([]string{"::ffff:0.0.0.0/96"})
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "[::ffff:203.0.113.7]:44444"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	ip := extractClientIPWithTrustedProxies(req, cidrs)
	if ip != nil && ip.String() == "1.2.3.4" {
		t.Fatalf("FAIL: XFF spoofed through the v4-mapped trust entry (client IP %s)", ip)
	}
}

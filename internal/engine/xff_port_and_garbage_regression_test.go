package engine

import (
	"net"
	"net/http/httptest"
	"testing"
)

// Regression: the X-Forwarded-For walk skipped entries net.ParseIP rejects,
// so a trusted proxy appending "ip:port" (Azure Application Gateway) was
// stepped over and a client-forged entry further left became the client IP,
// defeating IP ACL and rate limits.
func TestExtractClientIPForwardedEntryParsing(t *testing.T) {
	cidrs := parseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	cases := []struct {
		name, xff, realIP, want string
	}{
		{"ipv4 with port", "6.6.6.6, 203.0.113.7:51234", "", "203.0.113.7"},
		{"bracketed ipv6 with port", "6.6.6.6, [2001:db8::7]:443", "", "2001:db8::7"},
		{"bracketed ipv6 without port", "6.6.6.6, [2001:db8::8]", "", "2001:db8::8"},
		{"trusted hop with port", "203.0.113.9, 10.0.0.4:8080", "", "203.0.113.9"},
		{"garbage stops the walk at the last trusted hop", "6.6.6.6, garbage, 10.0.0.4", "", "10.0.0.4"},
		{"garbage right after the peer resolves to the peer", "6.6.6.6, garbage", "", "10.0.0.1"},
		{"x-real-ip ignored once xff is present", "10.0.0.2", "6.6.6.6", "10.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = "10.0.0.1:12345"
			r.Header.Set("X-Forwarded-For", tc.xff)
			if tc.realIP != "" {
				r.Header.Set("X-Real-IP", tc.realIP)
			}
			got := extractClientIPWithTrustedProxies(r, cidrs)
			if got == nil || !got.Equal(net.ParseIP(tc.want)) {
				t.Fatalf("client IP = %v, want %s", got, tc.want)
			}
		})
	}
}

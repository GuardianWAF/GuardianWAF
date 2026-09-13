package engine

import (
	"net"
	"net/http"
	"testing"
)

// Regression: extractClientIPWithTrustedProxies read X-Forwarded-For via
// r.Header.Get — the FIRST header line only. Duplicate X-Forwarded-For lines
// are legal on the wire and Go's server preserves them as separate
// header-map values, so the documented "rightmost non-trusted IP" walk was
// judged on the first line alone: with a trusted proxy appending the real
// client to a later line, an attacker-chosen first line decided the client
// IP that keys IP ACL, rate limiting, and auto-bans. Same
// attacker-orderable-value family as the ctx.Cookies / multi-value header
// capture fixes.

// The discriminator: the attacker-chosen entry sits in the FIRST line while
// the proxy appended the real client to a LATER line. The walk must join all
// lines in order of appearance and return the globally rightmost untrusted
// entry.
func TestExtractClientIPAllHeaderLinesRightmost(t *testing.T) {
	cidrs := parseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "10.0.0.9:5555" // trusted proxy
	req.Header["X-Forwarded-For"] = []string{"6.6.6.6", "9.9.9.9, 203.0.113.7"}

	ip := extractClientIPWithTrustedProxies(req, cidrs)
	if ip == nil || !ip.Equal(net.ParseIP("203.0.113.7")) {
		t.Fatalf("FAIL: multi-line XFF: got %v, want 203.0.113.7 (first-line-only read returns attacker-chosen 6.6.6.6)", ip)
	}
}

// The pre-fix single-line form keeps its exact behavior.
func TestExtractClientIPSingleLineUnchanged(t *testing.T) {
	cidrs := parseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "10.0.0.9:5555"
	req.Header.Set("X-Forwarded-For", "9.9.9.9, 203.0.113.7")

	ip := extractClientIPWithTrustedProxies(req, cidrs)
	if ip == nil || !ip.Equal(net.ParseIP("203.0.113.7")) {
		t.Fatalf("FAIL: single-line XFF: got %v, want 203.0.113.7", ip)
	}
}

// An untrusted direct peer gets no header trust at all.
func TestExtractClientIPUntrustedPeerHeaderIgnored(t *testing.T) {
	cidrs := parseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "192.0.2.9:5555"
	req.Header.Set("X-Forwarded-For", "6.6.6.6")

	ip := extractClientIPWithTrustedProxies(req, cidrs)
	if ip == nil || !ip.Equal(net.ParseIP("192.0.2.9")) {
		t.Fatalf("FAIL: untrusted peer: got %v, want 192.0.2.9 (RemoteAddr)", ip)
	}
}

// An all-trusted XFF chain falls back to RemoteAddr.
func TestExtractClientIPAllTrustedXFallsBackToRemote(t *testing.T) {
	cidrs := parseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "10.0.0.9:5555"
	req.Header.Set("X-Forwarded-For", "10.0.0.2, 10.0.0.3")

	ip := extractClientIPWithTrustedProxies(req, cidrs)
	if ip == nil || !ip.Equal(net.ParseIP("10.0.0.9")) {
		t.Fatalf("FAIL: all-trusted XFF: got %v, want 10.0.0.9 (RemoteAddr)", ip)
	}
}

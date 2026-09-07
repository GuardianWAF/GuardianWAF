package openredirect

import (
	"net/url"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// TestHostname_StripsPortFromBracketedIPv6 pins the host-extraction contract:
// for a bracketed IPv6 literal the host is everything between the brackets and
// anything after ']' is a port. The previous implementation only used the
// leading '[' to skip colon-splitting and then TrimSuffix("]"), which is a
// no-op when a port follows, so "[2001:db8::1]:8443" returned
// "2001:db8::1]:8443" — port and a stray ']' included.
func TestHostname_StripsPortFromBracketedIPv6(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"[2001:db8::1]:8443", "2001:db8::1"},
		{"[::1]:8080", "::1"},
		{"[::1]", "::1"},
		{"example.com:8080", "example.com"},
		{"example.com", "example.com"},
		{"192.168.1.10", "192.168.1.10"},
		{"[::1", "::1"}, // malformed: no closing bracket, returned as before
	}
	for _, c := range cases {
		if got := hostname(c.in); got != c.want {
			t.Errorf("hostname(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestSameHostAbsoluteURL_BracketedIPv6WithPort is the regression that the
// mangled reqHost caused: on a vhost whose Host header is "[v6]:port", every
// same-host absolute redirect compared its parsed host ("2001:db8::1")
// against "2001:db8::1]:8443", mismatched, and was scored 60 -> ActionBlock.
func TestSameHostAbsoluteURL_BracketedIPv6WithPort(t *testing.T) {
	d := NewDetector(true, 1.0)
	const host = "[2001:db8::1]:8443"
	const target = "http://[2001:db8::1]:8443/admin"

	// Query-parameter branch.
	ctx := makeCtx(host, "next="+url.QueryEscape(target), nil)
	result := d.Process(ctx)
	if len(result.Findings) != 0 {
		t.Fatalf("same-host absolute URL on %s should not trigger, got %d findings: %+v",
			host, len(result.Findings), result.Findings)
	}
	if result.Action != engine.ActionPass {
		t.Fatalf("same-host absolute URL on %s should pass, got %v", host, result.Action)
	}

	// Location-header branch: same host extraction, same verdict.
	ctxHdr := makeCtx(host, "", map[string][]string{
		"Location": {target},
	})
	resultHdr := d.Process(ctxHdr)
	if len(resultHdr.Findings) != 0 {
		t.Fatalf("same-host Location header on %s should not trigger, got %d findings: %+v",
			host, len(resultHdr.Findings), resultHdr.Findings)
	}
}

// TestDifferentHostBracketedIPv6StillFlagged guards against over-correcting:
// an absolute URL pointing at a *different* host than the bracketed-IPv6 vhost
// must keep triggering.
func TestDifferentHostBracketedIPv6StillFlagged(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := makeCtx("[2001:db8::1]:8443", "next="+url.QueryEscape("http://[2001:db8::2]/steal"), nil)
	result := d.Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatal("redirect to a different host should still trigger on a bracketed-IPv6 vhost")
	}
	if result.Action != engine.ActionBlock {
		t.Fatalf("redirect to a different host should block, got %v", result.Action)
	}
}

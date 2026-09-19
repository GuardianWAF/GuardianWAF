package ssrf

// Regression (bug-hunt round 2026-09-18-r16, extending the asymmetry-sweep
// family from the round-9/25 sweep note): all three host-extraction loops in
// ssrf.go scanned the authority WITHOUT RFC 3986's userinfo rule — '@' is not
// a terminator, so "http://a@10.0.0.5/" extracted the "host" "a@10.0.0.5",
// ParseIPv4 rejected it, and the private-IP classification never fired. The
// scheme-ful form was masked by checkURLCredential's 70-score credential
// signal, but the PROTOCOL-RELATIVE form (//a@10.0.0.5/ — the exact shape the
// round-87 "//" support exists for: backends that fetch scheme-relative URLs)
// produced ZERO findings, and the v6 form (http://x@[::1]/) lost its
// classification because the ':' inside the userinfo terminated the host scan
// before the bracket. RFC 3986: everything up to the LAST '@' in the
// authority is userinfo; the host is what follows.

import (
	"strings"
	"testing"
)

func TestDetect_UserinfoHostStillClassified(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		keyword string // expected classification fragment
	}{
		{"scheme-ful v4", "http://a@10.0.0.5/", "private IP range"},
		{"userinfo with password", "http://user:pass@10.0.0.5/", "private IP range"},
		{"protocol-relative", "//a@10.0.0.5/", "private IP range"},
		{"protocol-relative decimal", "//a@2130706433", "Decimal encoded IP"},
		{"bracketed v6 with userinfo", "http://x@[::1]/", "IPv6 private"},
	}
	for _, tc := range cases {
		findings := Detect(tc.input, "query")
		found := false
		for _, f := range findings {
			if strings.Contains(f.Description, tc.keyword) {
				found = true
			}
		}
		if !found {
			t.Fatalf("FAIL: %s (%q) produced %d findings, none with the %q classification (%+v) — the host after the last '@' must be classified", tc.name, tc.input, len(findings), tc.keyword, findings)
		}
	}
}

// Control: the plain forms keep firing.
func TestDetect_PlainPrivateHostStillDetected(t *testing.T) {
	for _, input := range []string{"http://10.0.0.5/", "//10.0.0.5/", "http://2130706433"} {
		findings := Detect(input, "query")
		if len(findings) == 0 {
			t.Fatalf("FAIL: harness control — %q must keep its findings, got 0", input)
		}
	}
}

// Control: userinfo does not invert the host — in "a@10.0.0.5@evil.com" the
// real host is everything after the LAST '@' (evil.com, public), so no
// private classification may fire.
func TestDetect_UserinfoLastAtWins(t *testing.T) {
	findings := Detect("http://a@10.0.0.5@evil.com/", "query")
	for _, f := range findings {
		if strings.Contains(f.Description, "private IP range") {
			t.Fatalf("FAIL: userinfo must strip up to the LAST '@' — %q classified the public host as private (%+v)", "http://a@10.0.0.5@evil.com/", findings)
		}
	}
}

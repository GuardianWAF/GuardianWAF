package ssrf

import (
	"strings"
	"testing"
)

// Regression: checkPrivateIPs scanned the prefix list {"http://",
// "https://", "//"} with three independent loops, so the "//" inside a
// scheme-ful URL's own prefix matched again and the same host was classified
// twice: http://10.0.0.5 fired the private-range finding at 65x2, and
// http://127.0.0.1 totaled 80 (localhost pattern) + 65x2. Duplicate counting
// crosses the >= 50 block line for requests a single count would only log.
//
// The fix dedups candidates by absolute host position. A shape guard ("//"
// right after ':') would also have dropped every non-http(s) scheme-ful host
// (ssh://10.0.0.5) and nested schemes (http://http://10.0.0.5) that only the
// "//" loop reaches — those stay pinned below.

func countDesc(input, descPart string) int {
	n := 0
	for _, f := range Detect(input, "query") {
		if strings.Contains(f.Description, descPart) {
			n++
		}
	}
	return n
}

// Each range finding must fire exactly once for a scheme-ful URL. Covers the
// IPv4 dotted branch, the loopback classification, and the IPv6 bracket
// branch.
func TestDetectSchemeFulRangeFindingsSingleProcessed(t *testing.T) {
	if n := countDesc("http://10.0.0.5/admin", "private IP range"); n != 1 {
		t.Fatalf("FAIL: http://10.0.0.5/admin produced %d private-range findings, want exactly 1", n)
	}
	if n := countDesc("https://10.0.0.5/admin", "private IP range"); n != 1 {
		t.Fatalf("FAIL: https://10.0.0.5/admin produced %d private-range findings, want exactly 1", n)
	}
	if n := countDesc("http://127.0.0.1/admin", "loopback IP range"); n != 1 {
		t.Fatalf("FAIL: http://127.0.0.1/admin produced %d loopback-range findings, want exactly 1", n)
	}
	if n := countDesc("http://[::1]/", "IPv6 private/link-local"); n != 1 {
		t.Fatalf("FAIL: http://[::1]/ produced %d IPv6 branch findings, want exactly 1", n)
	}
}

// Controls: the protocol-relative dotted form stays detected exactly once,
// non-http(s) scheme-ful hosts keep their finding (reachable only through
// the "//" loop — a ':'-shape guard would zero them), nested schemes keep
// theirs (the scheme loop's own idx=hostEnd advance skips the overlapping
// occurrence), the round-86 no-doubling pin for the encoded-IP checks holds,
// and an unrelated public host stays clean.
func TestDetectSchemeFulDedupControls(t *testing.T) {
	if n := countDesc("//10.0.0.5/admin", "private IP range"); n != 1 {
		t.Fatalf("FAIL: //10.0.0.5/admin produced %d private-range findings, want exactly 1", n)
	}
	if n := countDesc("ssh://10.0.0.5/", "private IP range"); n != 1 {
		t.Fatalf("FAIL: ssh://10.0.0.5/ produced %d private-range findings, want exactly 1 (non-http scheme coverage)", n)
	}
	if n := countDesc("http://http://10.0.0.5", "private IP range"); n != 1 {
		t.Fatalf("FAIL: http://http://10.0.0.5 produced %d private-range findings, want exactly 1 (nested-scheme coverage)", n)
	}
	if n := len(Detect("http://2130706433/admin", "query")); n != 2 {
		t.Fatalf("FAIL: http://2130706433/admin produced %d findings, want exactly 2", n)
	}
	if s := detectScore("https://example.com/assets/app.js"); s != 0 {
		t.Fatalf("FAIL: https://example.com scored %d, expected clean", s)
	}
}

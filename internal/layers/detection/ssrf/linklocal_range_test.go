package ssrf

import (
	"strings"
	"testing"
)

// Regression: checkPrivateIPs classified dotted hosts only with
// IsLoopback || IsPrivateIP. ipcheck.IsLinkLocal (169.254/16, RFC 3927 — the
// range hosting the pinned cloud-metadata endpoints) existed, was
// unit-tested, and was called by nothing, so every dotted 169.254/16 host
// except the two pinned metadata literals produced zero findings, while the
// IPv6 branch flagged the equivalent fe80::/10 range at 70/Critical and the
// encoded spellings were caught by checkEncodedIPs. The detector blocks
// directly at score >= 50, so the gap was a real detection hole.
func TestDetectDottedLinkLocalRange(t *testing.T) {
	for _, in := range []string{
		"http://169.254.0.1/admin",
		"http://169.254.42.42/",
		"http://169.254.255.254:8080/",
	} {
		if s := detectScore(in); s == 0 {
			t.Fatalf("FAIL: %s produced zero findings (dotted 169.254/16 link-local invisible)", in)
		}
		if !detectHasDesc(in, "link-local") {
			t.Fatalf("FAIL: %s findings lack a link-local classification", in)
		}
	}
}

// Range boundaries: hosts outside 169.254/16 must not be classified as
// link-local (IsLinkLocal requires exactly 169 in the first octet and 254 in
// the second).
func TestDetectLinkLocalBoundaries(t *testing.T) {
	for _, in := range []string{
		"http://169.255.0.1/",
		"http://169.253.0.1/",
		"http://170.254.0.1/",
	} {
		if detectHasDesc(in, "link-local") {
			t.Fatalf("FAIL: %s flagged as link-local (outside 169.254/16)", in)
		}
	}
}

// Controls: the pinned metadata literals, the IPv6 link-local branch, the
// encoded spellings, and a benign public host keep their established
// behavior.
func TestDetectLinkLocalControls(t *testing.T) {
	if s := detectScore("http://169.254.169.254/latest/meta-data/"); s < 95 {
		t.Fatalf("FAIL: AWS metadata literal scored %d, want >= 95", s)
	}
	if s := detectScore("http://[fe80::1]/internal"); s < 60 {
		t.Fatalf("FAIL: fe80::1 scored %d, want >= 60", s)
	}
	if s := detectScore("http://2852039169/"); s == 0 {
		t.Fatal("FAIL: decimal-encoded link-local produced zero findings")
	}
	if s := detectScore("https://example.com/assets/app.js"); s != 0 {
		t.Fatalf("FAIL: example.com scored %d, expected clean", s)
	}
}

func detectHasDesc(input, substr string) bool {
	for _, f := range Detect(input, "query") {
		if strings.Contains(f.Description, substr) {
			return true
		}
	}
	return false
}

package ssrf

import "testing"

func totalScore(in string) int {
	total := 0
	for _, f := range Detect(in, "body") {
		total += f.Score
	}
	return total
}

// TestURLCredential_AuthorityStopsAtDelimiter pins a false positive that broke
// ordinary API traffic.
//
// checkURLCredential ended the URL authority only at the first "/". A URL with
// no path therefore ran to the end of the input, so in an embedded document the
// "authority" swallowed unrelated text — and any later "@" was read as URL
// credentials. An ordinary profile update carrying both a website and an e-mail
// address scored 70 and was blocked.
func TestURLCredential_AuthorityStopsAtDelimiter(t *testing.T) {
	benign := []string{
		`{"website":"http://example.com","email":"alice@example.com"}`,
		`{"homepage":"https://example.org","contact":"bob@example.org"}`,
		`website=http://example.com&email=alice@example.com`,
		`Visit http://example.com or mail alice@example.com`,
		`<a href="http://example.com">x</a> alice@example.com`,
	}
	for _, in := range benign {
		t.Run(in, func(t *testing.T) {
			if s := totalScore(in); s >= 50 {
				t.Fatalf("benign input scored %d (>= block threshold): %q", s, in)
			}
		})
	}
}

// TestURLCredential_RealCredentialsStillDetected guards against the boundary
// fix hiding genuine credential-in-URL SSRF payloads.
func TestURLCredential_RealCredentialsStillDetected(t *testing.T) {
	attacks := []string{
		"http://evil.com@127.0.0.1/admin",
		"https://user:pass@internal.corp/",
		"http://attacker@169.254.169.254/latest/meta-data/",
	}
	for _, in := range attacks {
		t.Run(in, func(t *testing.T) {
			if s := totalScore(in); s == 0 {
				t.Fatalf("credential-in-URL payload not detected: %q", in)
			}
		})
	}
}

// TestHostBoundary_TrailingDotIsTheSameHost pins the root-label bypass.
// "127.0.0.1." is the fully-qualified form of 127.0.0.1 and resolves
// identically, but a trailing dot used to be treated as continuing the
// hostname, so the pattern never matched.
func TestHostBoundary_TrailingDotIsTheSameHost(t *testing.T) {
	for _, in := range []string{
		"http://127.0.0.1./admin",
		"http://127.0.0.1.",
		"http://localhost./x",
	} {
		t.Run(in, func(t *testing.T) {
			if totalScore(in) == 0 {
				t.Fatalf("fully-qualified localhost form not detected: %q", in)
			}
		})
	}
}

// TestHostBoundary_LongerAddressStillNotMatched is the reason the trailing-dot
// rule is narrow: a dot followed by another label is a different host, and
// 127.0.0.100 must not match the pattern 127.0.0.1.
func TestHostBoundary_LongerAddressStillNotMatched(t *testing.T) {
	for _, s := range []string{"127.0.0.100", "127.0.0.10"} {
		if containsHostPattern("http://"+s+"/x", "127.0.0.1") {
			t.Fatalf("%q must not match the 127.0.0.1 host pattern", s)
		}
	}
	if !containsHostPattern("http://127.0.0.1/x", "127.0.0.1") {
		t.Fatal("exact host must still match")
	}
}

// TestAuthorityEnd covers the delimiter set directly.
func TestAuthorityEnd(t *testing.T) {
	tests := []struct{ in, want string }{
		{"example.com/path", "example.com"},
		{"example.com?a=1", "example.com"},
		{"example.com#frag", "example.com"},
		{`example.com","email":"a@b.c"}`, "example.com"},
		{"example.com or text", "example.com"},
		{"user:pass@example.com/x", "user:pass@example.com"},
		{"example.com&email=a@b.c", "example.com"},
		{"example.com", "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := tt.in[:authorityEnd(tt.in)]; got != tt.want {
				t.Fatalf("authorityEnd(%q) -> %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

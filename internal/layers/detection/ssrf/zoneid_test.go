package ssrf

import "testing"

// Regression (2026-09-15 round): the IPv6 branch of checkPrivateIPs parsed
// the bracketed literal with net.ParseIP, which rejects any zone identifier.
// Bracketed zone forms are legal URLs — "[::1%25eth0]" percent-decodes to
// "[::1%eth0]" — and Go backends dial them directly, so loopback and
// link-local targets behind a zone produced zero findings while the same
// addresses without the zone were flagged 70/Critical. The fix strips the
// zone (opaque to classification) and re-parses the address part.
func TestDetect_ZoneIDForms(t *testing.T) {
	for _, in := range []string{
		"http://[::1%25eth0]/admin", // raw percent-encoded zone
		"http://[::1%eth0]/x",       // percent-decoded zone
		"http://[fe80::1%25wlan0]/", // link-local with zone
	} {
		if s := detectScore(in); s == 0 {
			t.Fatalf("FAIL: %s produced zero findings (zone-hidden loopback/link-local invisible)", in)
		}
		if !detectHasDesc(in, "IPv6 private/link-local/unspecified") {
			t.Fatalf("FAIL: %s findings lack a v6 classification", in)
		}
	}
}

// Boundary: a PUBLIC address carrying a zone stays clean — the zone is
// opaque to classification, not a widening of it.
func TestDetect_ZoneIDPublicStaysClean(t *testing.T) {
	if s := detectScore("http://[2001:db8::1%25eth0]/x"); s != 0 {
		t.Fatalf("FAIL: public IPv6 with zone scored %d, want 0", s)
	}
}

// Controls: the plain spellings keep their established behavior.
func TestDetect_ZoneIDControls(t *testing.T) {
	if s := detectScore("http://[::1]/admin"); s < 60 {
		t.Fatalf("FAIL: [::1] scored %d, want >= 60", s)
	}
	if s := detectScore("http://[fe80::1]/internal"); s < 60 {
		t.Fatalf("FAIL: fe80::1 scored %d, want >= 60", s)
	}
	if s := detectScore("https://example.com/app.js"); s != 0 {
		t.Fatalf("FAIL: example.com scored %d, want 0", s)
	}
}

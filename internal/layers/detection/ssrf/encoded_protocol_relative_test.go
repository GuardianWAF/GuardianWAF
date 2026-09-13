package ssrf

import "testing"

// Regression: checkEncodedIPs scanned only "http://" and "https://" prefixes,
// so protocol-relative encoded-IP URLs produced zero findings while the
// protocol-relative DOTTED form (//10.0.0.5) was caught via checkPrivateIPs,
// which includes "//" in its prefix list. A backend fetching a user-supplied
// URL relative to its own scheme turns ?url=//2130706433 into
// https://2130706433 — the encoded forms are equally live payloads.

func TestDetectProtocolRelativeEncodedIPs(t *testing.T) {
	for _, in := range []string{
		"//2130706433/admin",
		"//0x7f000001/admin",
		"//127.1/admin",
		"//0177.0.0.1/admin",
	} {
		if s := detectScore(in); s == 0 {
			t.Fatalf("FAIL: %s produced zero findings (protocol-relative encoded IP invisible)", in)
		}
	}
}

// The scheme-tail guard must keep scheme-ful URLs single-processed: the "//"
// inside "http://" is skipped by the protocol-relative scan, so an
// http-encoded loopback still yields exactly its two findings (decimal match
// + loopback resolve bonus), not four.
func TestDetectSchemeFulEncodedIPNotDoubled(t *testing.T) {
	n := len(Detect("http://2130706433/admin", "query"))
	if n != 2 {
		t.Fatalf("FAIL: http://2130706433/admin produced %d findings, want exactly 2 (decimal match + loopback resolve bonus)", n)
	}
}

// Controls: the dotted protocol-relative form, the scheme-ful forms, and a
// clean host.
func TestDetectProtocolRelativeControls(t *testing.T) {
	for _, in := range []string{
		"//10.0.0.5/admin",
		"http://2130706433/admin",
		"http://127.0.0.1/admin",
	} {
		if s := detectScore(in); s == 0 {
			t.Fatalf("FAIL: %s produced zero findings", in)
		}
	}
	if s := detectScore("//example.com/assets/app.js"); s != 0 {
		t.Fatalf("FAIL: //example.com scored %d, expected clean", s)
	}
}

package ssrf

import (
	"strings"
	"testing"
)

// Regression (2026-09-15 round): addresses that dial the local machine were
// unclassified —
//
//   - IPv6 unspecified: the v6 branch of checkPrivateIPs tested
//     IsPrivate / IsLinkLocalUnicast / IsLoopback but never IsUnspecified,
//     so http://[::]/ and its spelled-out form produced zero findings;
//   - 0/8 short form: http://0/ is inet_aton("0") = 0.0.0.0, but
//     ParseIPv4 needs 4 parts, ParseDecimalIP rejects n < 256, and
//     checkLocalhostPatterns pinned only the literal "0.0.0.0";
//   - dotted 0/8: http://0.0.0.2/, http://0.13.37.7/ parse as IPv4 but no
//     range classifier matched — while Linux treats all of 0/8 as local.
//
// All are on the OWASP localhost-alternatives list and the detector blocks
// directly at score >= 50, so each was a real detection hole.
func TestDetect_LocalMachineAddresses(t *testing.T) {
	for _, in := range []string{
		"http://[::]/admin",
		"http://[0:0:0:0:0:0:0:0]/x",
		"http://0/",
		"https://0/admin",
		"http://0.0.0.2/x",
		"http://0.13.37.7/",
	} {
		if s := detectScore(in); s == 0 {
			t.Fatalf("FAIL: %s produced zero findings (local-machine address unclassified)", in)
		}
	}
}

// The v4 branch classifies 0/8 as "this-network"; the v6 branch message
// names the unspecified address. Description checks keep the classifications
// pinned, not just the scores.
func TestDetect_LocalAddressClassifications(t *testing.T) {
	if !detectHasLocalDesc("http://0.0.0.2/x", "this-network") {
		t.Fatal("FAIL: dotted 0/8 host lacks a this-network classification")
	}
	if !detectHasLocalDesc("http://[::]/admin", "unspecified") {
		t.Fatal("FAIL: [::] lacks an unspecified classification")
	}
}

// Range and shape boundaries: public addresses, and hostnames that merely
// start with "0", must stay clean; the pinned spellings keep firing.
func TestDetect_LocalRangeBoundariesAndControls(t *testing.T) {
	for _, in := range []string{
		"http://1.1.1.1/",        // public unicast, not 0/8
		"http://0.example.com/",  // "0" is not a host boundary before a label
		"https://example.com/js", // benign host
	} {
		if s := detectScore(in); s != 0 {
			t.Fatalf("FAIL: %s scored %d, want 0", in, s)
		}
	}

	if s := detectScore("http://0.0.0.0/"); s < 85 {
		t.Fatalf("FAIL: 0.0.0.0 scored %d, want >= 85", s)
	}
	if s := detectScore("http://[::1]/admin"); s < 60 {
		t.Fatalf("FAIL: [::1] scored %d, want >= 60", s)
	}
	if s := detectScore("http://10.0.0.5/internal"); s < 65 {
		t.Fatalf("FAIL: 10.0.0.5 scored %d, want >= 65", s)
	}
	if !detectHasLocalDesc("http://100.100.100.200/latest/meta-data/", "Alibaba") {
		t.Fatal("FAIL: Alibaba metadata literal lost its finding")
	}
}

func detectHasLocalDesc(input, substr string) bool {
	for _, f := range Detect(input, "query") {
		if strings.Contains(f.Description, substr) {
			return true
		}
	}
	return false
}

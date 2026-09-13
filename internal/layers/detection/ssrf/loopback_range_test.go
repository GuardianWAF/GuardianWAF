package ssrf

import "testing"

// Regression: checkPrivateIPs classified dotted hosts but SKIPPED loopback
// ("handled by checkLocalhostPatterns"), and checkLocalhostPatterns only pins
// the spellings "http://127.0.0.1" and "http://127.1" — so every other dotted
// 127/8 host (http://127.0.0.2, http://127.8.8.8) produced zero findings,
// while the detector's own IPv6 branch and the encoded-IP checks flagged the
// same addresses. This detector blocks directly at score >= 50, so the gap
// was a real detection hole, not missing telemetry.

func detectScore(input string) int {
	score := 0
	for _, f := range Detect(input, "query") {
		score += f.Score
	}
	return score
}

func TestDetectDottedLoopbackRange(t *testing.T) {
	for _, in := range []string{
		"http://127.0.0.2:8080/admin",
		"http://127.8.8.8/",
		"https://127.20.30.40/x",
	} {
		if s := detectScore(in); s == 0 {
			t.Fatalf("FAIL: %s produced zero findings (dotted 127/8 loopback invisible)", in)
		}
	}
}

// Controls: the pinned localhost spellings, the private-range check, and the
// encoded-IP path keep working; an unrelated public host stays clean.
func TestDetectLoopbackControls(t *testing.T) {
	for _, in := range []string{
		"http://127.0.0.1/",
		"http://127.1/",
		"http://10.0.0.5/",
		"http://2130706433/",
	} {
		if s := detectScore(in); s == 0 {
			t.Fatalf("FAIL: %s produced zero findings", in)
		}
	}
	if s := detectScore("https://example.com/assets/app.js"); s != 0 {
		t.Fatalf("FAIL: https://example.com scored %d, expected clean", s)
	}
}

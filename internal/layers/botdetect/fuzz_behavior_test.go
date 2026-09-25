package botdetect

import (
	"fmt"
	"testing"
	"time"
)

// FuzzBehavior drives the behavior analyzer with hostile request sequences.
// Properties: never panics; score stays within [0, 210] (50+60+45+55); every
// finding comes from the four known strings; the tracker map never exceeds
// its cap; consecutive Analyze calls agree (no state churn without new
// records).
func FuzzBehavior(f *testing.F) {
	// Normal browsing: few requests, varied timing.
	f.Add("10.0.0.1", "/login", false, int64(120), int64(0), 6)
	// Machine-like: uniform timing, same path.
	f.Add("10.0.0.2", "/api", false, int64(5), int64(0), 20)
	// Error flood.
	f.Add("10.0.0.3", "/admin", true, int64(30), int64(0), 30)
	// Path enumeration.
	f.Add("10.0.0.4", "/item", false, int64(50), int64(0), 25)
	// Edge shapes: zero/negative latency, hostile strings, zero rounds.
	f.Add("10.0.0.5", "", false, int64(0), int64(0), 3)
	f.Add("10.0.0.6", "\x00\xff/..", true, int64(-5), int64(0), 4)
	f.Add("", "x", false, int64(9_000_000_000_000), int64(0), 2)
	f.Add("10.0.0.7", "/x", false, int64(1), int64(0), 0)

	f.Fuzz(func(t *testing.T, ip, path string, isError bool, latencyMs, _ int64, rounds int) {
		bm := NewBehaviorManager(DefaultBehaviorConfig())
		bm.maxEntries = 8 // shrink the cap so the boundedness pin is real

		n := rounds
		if n < 0 {
			n = 0
		}
		if n > 32 {
			n = 32
		}
		for i := 0; i < n; i++ {
			// A handful of derived IPs per sequence exercises the map cap.
			trackIP := fmt.Sprintf("%s-%d", ip, i%4)
			bm.Record(trackIP, fmt.Sprintf("%s/%d", path, i%10), isError && i%2 == 0, time.Duration(latencyMs+int64(i))*time.Millisecond)
			if i%4 == 0 {
				bm.MarkError(trackIP)
			}
		}

		score, findings := bm.Analyze(ip + "-0")
		if score < 0 || score > 210 {
			t.Fatalf("score %d outside [0, 210]", score)
		}
		known := map[string]bool{
			"high request rate detected":           true,
			"excessive path enumeration detected":  true,
			"high error rate detected":             true,
			"machine-like request timing detected": true,
		}
		if len(findings) > 4 {
			t.Fatalf("got %d findings, max is 4", len(findings))
		}
		for _, fnd := range findings {
			if !known[fnd] {
				t.Fatalf("unknown finding %q", fnd)
			}
		}
		score2, findings2 := bm.Analyze(ip + "-0")
		if score2 != score || len(findings2) != len(findings) {
			t.Fatalf("Analyze not deterministic: %d/%v then %d/%v", score, findings, score2, findings2)
		}

		bm.Cleanup()
		if got := bm.TrackerCount(); got > 8 {
			t.Fatalf("tracker count %d exceeds cap 8", got)
		}
	})
}

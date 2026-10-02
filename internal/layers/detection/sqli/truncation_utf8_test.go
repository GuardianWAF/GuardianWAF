package sqli

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// The SQLi detector builds Finding.MatchedValue from request input and
// previously truncated it with a raw byte slice (`matched[:197] + "..."`).
// A multi-byte rune straddling the cut was split and the invalid sequence was
// stored in the evidence that flows into events, the dashboard, and traces.
//
// The engine's canonical TruncateEvidence is applied in ScoreAccumulator.Add,
// but it returns early once len <= 200 and the byte slice landed at exactly
// 200 (197 + "..."), so the engine re-truncation was a no-op and the
// corruption survived.
//
// Sibling detectors were already fixed for this exact defect: engine/finding.go,
// xxe.go, ai/analyzer.go, LFI, ssrf, sanitizer/validate.go, and xss.

// evi builds a value whose 3-byte '€' (U+20AC) straddles the 197-byte cut, so
// a naive `s[:197]` keeps a 2-byte fragment and drops the third byte.
func evi(prefix, suffix string) string {
	var b strings.Builder
	b.WriteString(strings.Repeat(prefix, 195))
	b.WriteRune('€')
	b.WriteString(strings.Repeat(suffix, 10))
	return b.String()
}

func TestMakeFinding_MatchedValueStaysValidUTF8(t *testing.T) {
	// Control: short ASCII evidence is untouched.
	if f := makeFinding(50, engine.SeverityHigh, "d", "aaa", "query", 1.0); f.MatchedValue != "aaa" {
		t.Fatalf("CONTROL BROKEN: short ASCII evidence was altered: %q", f.MatchedValue)
	}
	// Control: long ASCII still truncates to the same shape as before.
	ascii := strings.Repeat("a", 250)
	if f := makeFinding(50, engine.SeverityHigh, "d", ascii, "query", 1.0); f.MatchedValue != ascii[:197]+"..." {
		t.Fatalf("CONTROL BROKEN: ASCII truncation shape changed: %q", f.MatchedValue)
	}

	f := makeFinding(50, engine.SeverityHigh, "d", evi("x", "y"), "query", 1.0)
	if !utf8.ValidString(f.MatchedValue) {
		t.Errorf("FAIL: makeFinding stored invalid UTF-8 in MatchedValue (ends %x)",
			f.MatchedValue[len(f.MatchedValue)-6:])
	}
}

// Detect is the real production entry point. checkUnionSelect skips comment
// tokens while scanning for SELECT, so a long /* ... */ block between UNION and
// SELECT makes extractRange produce a naturally >200-byte matched value.
func TestDetect_FindingMatchedValueIsValidUTF8(t *testing.T) {
	ctrl := Detect("UNION /*"+strings.Repeat("a", 210)+"*/ SELECT", "query")
	if len(ctrl) == 0 {
		t.Fatalf("CONTROL BROKEN: long ASCII UNION SELECT produced no findings")
	}

	payload := "UNION /*" + strings.Repeat("a", 188) + "€" + strings.Repeat("b", 10) + "*/ SELECT"
	fs := Detect(payload, "query")
	if len(fs) == 0 {
		t.Fatalf("CONTROL BROKEN: subject payload produced no findings")
	}
	for _, f := range fs {
		if !utf8.ValidString(f.MatchedValue) {
			t.Errorf("FAIL: finding %q carried invalid UTF-8 in MatchedValue (ends %x)",
				f.Description, f.MatchedValue[len(f.MatchedValue)-6:])
		}
	}
}

// Boundary: the rune must survive at each end of the cut, and truncation must
// never exceed the 200-byte cap.
func TestMakeFinding_RuneAtCutBoundary(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"split at cut", strings.Repeat("a", 195) + "€" + "b"},
		{"starts at cut", strings.Repeat("a", 197) + "€" + "b"},
		{"ends at cut", strings.Repeat("a", 194) + "€" + "b"},
	} {
		f := makeFinding(50, engine.SeverityHigh, "d", tc.in, "query", 1.0)
		if !utf8.ValidString(f.MatchedValue) {
			t.Errorf("FAIL (%s): result is invalid UTF-8 (ends %x)",
				tc.name, f.MatchedValue[len(f.MatchedValue)-6:])
		}
		if len(f.MatchedValue) > 200 {
			t.Errorf("FAIL (%s): result is %d bytes, over the 200-byte cap", tc.name, len(f.MatchedValue))
		}
	}
}

// Precision control: multi-byte input that fits under the cap must pass
// through completely untouched.
func TestMakeFinding_UnderLimitMultiByteUntouched(t *testing.T) {
	short := "SELECT '€ ünïcode' FROM t"
	f := makeFinding(50, engine.SeverityHigh, "d", short, "query", 1.0)
	if f.MatchedValue != short {
		t.Errorf("FAIL: under-limit multi-byte evidence was altered: %q", f.MatchedValue)
	}
}

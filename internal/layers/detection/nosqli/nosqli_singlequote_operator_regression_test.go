package nosqli

// Regression (bug-hunt round 2026-09-18-r9, extending the round-9/25 sweep
// note "paired constructs — both quote styles — handled on one side only"):
// checkInjectionOperators required DOUBLE-quote-delimited operators
// (injectionOperators entries embed literal `"` around each name), so the
// single-quoted Python-dict/JS-object notation {'$regex': '.*'} — the exact
// transport checkAuthBypass was fixed to handle in round 7/25 (cutset widened
// for {'$ne': ''}) — produced ZERO findings from this check. The missed
// findings feed the Accumulator's threshold scoring (40 per operator), so
// single-quoted operator payloads were under-scored relative to their
// double-quoted twins. The fix mirrors both quote styles; the quote
// requirement itself stays (bare "$modx"-style prose still never matches).

import (
	"testing"
)

// TestDetect_SingleQuotedInjectionOperator is the defect case: the
// single-quoted notation must score the same operator finding as the
// double-quoted form.
func TestDetect_SingleQuotedInjectionOperator(t *testing.T) {
	findings := Detect(`{'$regex': '.*'}`, "body")
	if len(findings) == 0 {
		t.Fatalf("FAIL: single-quoted operator {'$regex': '.*'} produced 0 findings — checkInjectionOperators matches only the double-quoted form; both quote styles must be handled")
	}
	for _, f := range findings {
		if f.Score <= 0 {
			t.Fatalf("FAIL: finding for single-quoted operator has non-positive score: %+v", f)
		}
	}
}

// Control: the double-quoted JSON form keeps being detected — the fix must
// not lose the existing form.
func TestDetect_DoubleQuotedInjectionOperatorStillDetected(t *testing.T) {
	findings := Detect(`{"$regex": ".*"}`, "body")
	found := false
	for _, f := range findings {
		if f.MatchedValue == "$regex" {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: harness control — double-quoted {\"$regex\": ...} must still produce the $regex finding, got %+v", findings)
	}
}

// Control: precision preserved — bare operator mentions in prose (no quotes)
// still never match, exactly as before the fix.
func TestDetect_BareOperatorProseNotMatched(t *testing.T) {
	findings := Detect("we benchmarked $regex performance and $modx templates", "body")
	for _, f := range findings {
		if f.Description == "NoSQL query operator in user input" {
			t.Fatalf("FAIL: harness control — bare unquoted operator prose must not match the quoted-only check, got %+v", f)
		}
	}
}

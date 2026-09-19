package sqli

// Regression (bug-hunt round 2026-09-18-r11, extending the asymmetry-sweep
// family from the round-9/25 sweep note): checkUnionSelect's lookahead
// skipped comment tokens and the interlude keyword ALL while hunting for
// SELECT, but SQL's union grammar is `UNION [ALL | DISTINCT] SELECT` —
// DISTINCT is the paired interlude keyword (and is classified TokenKeyword,
// keywords.go "DISTINCT": true). The lookahead therefore broke on DISTINCT:
// `1' UNION DISTINCT SELECT password FROM users--` missed the 90-Critical
// union-select finding and scored only ~20 from isolated keywords
// (IsDangerousKeyword covers UNION and SELECT but not FROM, and the
// multiple-keywords bonus needs >=3 distinct) — passing in enforce mode where
// the ALL form blocked at ~110.

import (
	"testing"
)

const unionDistinctPayload = "1' UNION DISTINCT SELECT password FROM users--"

// TestDetect_UnionDistinctSelectDetected is the defect case: the DISTINCT
// interlude must be skipped exactly like ALL so the union-select pattern fires.
func TestDetect_UnionDistinctSelectDetected(t *testing.T) {
	findings := Detect(unionDistinctPayload, "body")
	found := false
	for _, f := range findings {
		if f.Description == "UNION SELECT injection pattern detected" {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: %q produced %d findings, none with the UNION SELECT classification (%+v) — the DISTINCT interlude must be skipped like ALL", unionDistinctPayload, len(findings), findings)
	}
}

// Control: the ALL interlude keeps firing — the fix must not lose the
// existing form.
func TestDetect_UnionAllSelectStillDetected(t *testing.T) {
	findings := Detect("1' UNION ALL SELECT password FROM users--", "body")
	found := false
	for _, f := range findings {
		if f.Description == "UNION SELECT injection pattern detected" {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: harness control — the UNION ALL form must keep its union-select finding, got %+v", findings)
	}
}

// Control: precision — DISTINCT skipped but SELECT never reached means no
// union finding (e.g. prose or a bare interlude without a SELECT tail).
func TestDetect_UnionDistinctWithoutSelectNoFinding(t *testing.T) {
	findings := Detect("compare union distinct rates", "body")
	for _, f := range findings {
		if f.Description == "UNION SELECT injection pattern detected" {
			t.Fatalf("FAIL: harness control — union without a SELECT tail must not produce the union-select finding, got %+v", f)
		}
	}
}

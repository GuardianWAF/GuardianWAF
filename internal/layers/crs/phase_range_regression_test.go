package crs

import (
	"strconv"
	"testing"
)

// Regression (round 2026-09-18): parseActions' phase case rejected non-numeric
// values but accepted ANY integer. SecLang defines exactly five processing
// phases (ModSecurity Reference Manual v2.x, Processing Phases), so:
//   phase:9   loaded into rulesByPhase[9] — Process (phases 1-2) never
//             evaluated it: a silently dead rule;
//   phase:0 / negative values skipped the actions.Phase > 0 override and
//             silently aliased to the SecLang default phase 2.
// Out-of-range phases now fail the rule load (fail-closed, same policy as
// unsupported transformations).

func TestParseRejectsOutOfRangePhase(t *testing.T) {
	for _, phase := range []string{"0", "-1", "6", "9", "99"} {
		if _, err := NewParser().ParseFile(`SecRule ARGS "@rx x" "id:930020,phase:` + phase + `,deny"`); err == nil {
			t.Fatalf("phase:%s accepted at load — out-of-range phases must fail the rule load (SecLang has phases 1-5)", phase)
		}
	}
}

func TestParseRejectsOutOfRangePhaseOnSecAction(t *testing.T) {
	// parseActions is shared by SecRule, SecAction, and chain sections.
	if _, err := NewParser().ParseFile(`SecAction "id:930030,phase:7,pass"`); err == nil {
		t.Fatalf("SecAction phase:7 accepted at load")
	}
}

func TestParseRejectsOutOfRangePhaseInChainSection(t *testing.T) {
	line := `SecRule ARGS "@rx x" "id:930050,phase:1,chain" ARGS "@rx y" "phase:6,pass"`
	if _, err := NewParser().ParseFile(line); err == nil {
		t.Fatalf("phase:6 in the chained section accepted at load")
	}
}

func TestParseAcceptsSecLangPhases1to5(t *testing.T) {
	p := NewParser()
	for _, phase := range []int{1, 2, 3, 4, 5} {
		rules, err := p.ParseFile(`SecRule ARGS "@rx x" "id:930040,phase:` + strconv.Itoa(phase) + `,deny"`)
		if err != nil {
			t.Fatalf("phase:%d rejected: %v", phase, err)
		}
		// ParseFile accumulates rules across calls on the same parser; the
		// rule just parsed is the last one.
		if last := rules[len(rules)-1]; last.Phase != phase {
			t.Fatalf("phase:%d parsed as Phase %d", phase, last.Phase)
		}
	}
}

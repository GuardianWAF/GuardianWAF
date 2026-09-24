package crs

// Regression (round 2026-09-24-r10-skip-action-noop): RuleActions.Skip was
// parsed (parser.go "skip" case) but never read by the engine — a matched
// rule carrying skip:N must skip the next N rules in the same phase
// (SecLang), yet Process evaluated every rule in the phase list. The action
// was a silent no-op: the same "parsed but ignored" class as the
// logging-flag action clobber and the Stats parsed-vs-evaluated phase keys.
// Post-fix each phase carries its own skip window, the window opens on
// match, and disabled rules (not evaluated) do not consume it. skipAfter
// remains parsed-but-unsupported (marker semantics; out of scope here).

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func skipRuleLayer(t *testing.T, rulesText string, disabled map[string]bool) *Layer {
	t.Helper()
	rules, err := NewParser().ParseFile(rulesText)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	l := &Layer{
		config:        &Config{Enabled: true, AnomalyThreshold: 100},
		rules:         rules,
		disabledRules: disabled,
	}
	l.buildRuleMaps()
	return l
}

const skipTrioTmpl = `SecRule REQUEST_METHOD "@streq POST" "id:1001,phase:%s,pass,nolog,skip:1"
SecRule REQUEST_METHOD "@streq POST" "id:1002,phase:%s,pass,nolog"
SecRule REQUEST_METHOD "@streq POST" "id:1003,phase:%s,pass,nolog"
`

func TestProcess_SkipActionSkipsNextRules(t *testing.T) {
	// Phase 1 trio: 1001 matches (skip:1), 1002 skipped, 1003 still matches.
	trio1 := `SecRule REQUEST_METHOD "@streq POST" "id:1001,phase:1,pass,nolog,skip:1"
SecRule REQUEST_METHOD "@streq POST" "id:1002,phase:1,pass,nolog"
SecRule REQUEST_METHOD "@streq POST" "id:1003,phase:1,pass,nolog"
`
	res := skipRuleLayer(t, trio1, nil).Process(&engine.RequestContext{Method: "POST"})
	if len(res.Findings) != 2 || res.Findings[0].Category != "1001" || res.Findings[1].Category != "1003" {
		t.Fatalf("phase 1 findings = %v, want [1001 1003]", categories(res.Findings))
	}
	if res.Score != 2 {
		t.Fatalf("phase 1 Score = %d, want 2", res.Score)
	}

	// Phase 2 carries an independent window.
	trio2 := `SecRule REQUEST_METHOD "@streq POST" "id:1001,phase:2,pass,nolog,skip:1"
SecRule REQUEST_METHOD "@streq POST" "id:1002,phase:2,pass,nolog"
SecRule REQUEST_METHOD "@streq POST" "id:1003,phase:2,pass,nolog"
`
	res2 := skipRuleLayer(t, trio2, nil).Process(&engine.RequestContext{Method: "POST"})
	if len(res2.Findings) != 2 || res2.Findings[0].Category != "1001" || res2.Findings[1].Category != "1003" {
		t.Fatalf("phase 2 findings = %v, want [1001 1003]", categories(res2.Findings))
	}

	// skip:2 boundary: the next two rules are skipped, the fourth evaluates.
	quad := `SecRule REQUEST_METHOD "@streq POST" "id:1001,phase:1,pass,nolog,skip:2"
SecRule REQUEST_METHOD "@streq POST" "id:1002,phase:1,pass,nolog"
SecRule REQUEST_METHOD "@streq POST" "id:1003,phase:1,pass,nolog"
SecRule REQUEST_METHOD "@streq POST" "id:1004,phase:1,pass,nolog"
`
	res3 := skipRuleLayer(t, quad, nil).Process(&engine.RequestContext{Method: "POST"})
	if len(res3.Findings) != 2 || res3.Findings[0].Category != "1001" || res3.Findings[1].Category != "1004" {
		t.Fatalf("skip:2 findings = %v, want [1001 1004]", categories(res3.Findings))
	}

	// Disabled rules are not evaluated and do not consume the skip window:
	// 1001 matches (window=1), 1002 is disabled (window untouched), so 1003
	// is the rule the window skips.
	res4 := skipRuleLayer(t, trio1, map[string]bool{"1002": true}).Process(&engine.RequestContext{Method: "POST"})
	if len(res4.Findings) != 1 || res4.Findings[0].Category != "1001" {
		t.Fatalf("disabled-window findings = %v, want [1001]", categories(res4.Findings))
	}
}

func categories(findings []engine.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Category)
	}
	return out
}

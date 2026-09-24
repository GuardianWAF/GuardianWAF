package crs

// Regression (round 2026-09-24-r13-crs-macro-expansion): SecLang %{...}
// macros were never expanded — parseVarAction stored raw "%{tx.var}" in
// VarAction.Value and RuleOperator.Argument kept the raw text. applyVarActions'
// Atoi failed on the literal (delta 0, so macro-driven arithmetic such as
// "tx.anomaly_score=+%{tx.critical_anomaly_score}" — the core of CRS anomaly
// scoring — never moved a variable), and numeric operators compared against
// the literal "%{...}" string, so CRS-native threshold rules never matched.
// Post-fix both sites expand macros against the transaction (exact lookup,
// then case-insensitive; unknown or missing names expand to empty, matching
// ModSecurity). Variable-name casing between setvar and TX: readers must
// match exactly (GetVar is an exact map lookup; case-insensitive TX lookups
// are a separate ledgered observation).

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestProcess_MacroExpansion(t *testing.T) {
	rulesText := `SecRule REQUEST_METHOD "@streq POST" "id:3001,phase:1,pass,nolog,setvar:'tx.critical_score=7',setvar:'tx.floor=3',setvar:'tx.ANOMALY_SCORE=+%{tx.critical_score}'"
SecRule TX:ANOMALY_SCORE "@ge 7" "id:3002,phase:1,pass,nolog"
SecRule TX:critical_score "@ge %{tx.floor}" "id:3003,phase:1,pass,nolog"
SecRule REQUEST_METHOD "@streq POST" "id:3005,phase:1,pass,nolog"
`
	rules, err := NewParser().ParseFile(rulesText)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	l := &Layer{
		config:        &Config{Enabled: true, AnomalyThreshold: 100},
		rules:         rules,
		rulesByPhase:  map[int][]*Rule{1: rules},
		disabledRules: map[string]bool{},
	}
	l.buildRuleMaps()

	result := l.Process(&engine.RequestContext{Method: "POST"})

	var got []string
	for _, f := range result.Findings {
		got = append(got, f.Category)
	}
	// 3001 matches and sets the vars (including the macro arithmetic);
	// 3002 proves the arithmetic landed (ANOMALY_SCORE 7 >= 7); 3003 proves
	// the operator macro expanded (critical_score 7 >= floor 3); 3005 is
	// the control.
	if len(got) != 4 || got[0] != "3001" || got[1] != "3002" || got[2] != "3003" || got[3] != "3005" {
		t.Fatalf("macro-driven rules went missing: findings = %v, want [3001 3002 3003 3005]", got)
	}
	if result.Score != 4 {
		t.Fatalf("Score = %d, want 4 (four matched rules)", result.Score)
	}

	// Unknown/missing macro names expand to empty (ModSecurity semantics):
	// the arithmetic delta becomes 0, not a literal-text failure.
	l2 := &Layer{
		config:        &Config{Enabled: true, AnomalyThreshold: 100},
		disabledRules: map[string]bool{},
	}
	l2.rules, err = NewParser().ParseFile(`SecRule REQUEST_METHOD "@streq POST" "id:3011,phase:1,pass,nolog,setvar:'tx.MISSING_SCORE=+%{tx.does_not_exist}'"
SecRule TX:MISSING_SCORE "@streq 0" "id:3012,phase:1,pass,nolog"
`)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	l2.rulesByPhase = map[int][]*Rule{1: l2.rules}
	l2.buildRuleMaps()
	res2 := l2.Process(&engine.RequestContext{Method: "POST"})
	if len(res2.Findings) != 2 {
		t.Fatalf("missing-macro expansion findings = %d, want 2 (unknown macro expands to empty, delta 0)", len(res2.Findings))
	}
}

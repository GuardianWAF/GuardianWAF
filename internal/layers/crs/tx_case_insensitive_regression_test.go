package crs

// Regression (round 2026-09-24-r14-tx-case-lookup): Transaction.GetVar and
// SetVar used EXACT map keys, but ModSecurity stores TX variables in a
// case-insensitive table (apr_table), and CRS 3.x depends on it — actions
// write lowercase "tx.anomaly_score" while rules read "TX:ANOMALY_SCORE".
// Pre-fix the setvar landed under the lowercase key, the uppercase reader
// missed with "", and such rules never connected (the round-13 macro
// arithmetic was computed but invisible to uppercase readers). Post-fix both
// access points canonicalize names to upper case; same-case pairs are
// unaffected and mixed-case double-set overwrites deterministically.

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestProcess_TXVariableCaseInsensitive(t *testing.T) {
	rulesText := `SecRule REQUEST_METHOD "@streq POST" "id:4001,phase:1,pass,nolog,setvar:'tx.critical_score=5',setvar:'tx.anomaly_score=+%{tx.critical_score}'"
SecRule TX:ANOMALY_SCORE "@ge 5" "id:4002,phase:1,pass,nolog"
SecRule TX:critical_score "@ge 1" "id:4003,phase:1,pass,nolog"
SecRule REQUEST_METHOD "@streq POST" "id:4005,phase:1,pass,nolog"
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
	// 4001 sets the vars (lowercase setvar keys); 4002 reads the same
	// variable in UPPERCASE (the CRS idiom) — it must connect; 4003 is the
	// exact-case control; 4005 is the always-match control.
	if len(got) != 4 || got[0] != "4001" || got[1] != "4002" || got[2] != "4003" || got[3] != "4005" {
		t.Fatalf("case-mismatched TX rules went missing: findings = %v, want [4001 4002 4003 4005]", got)
	}
	if result.Score != 4 {
		t.Fatalf("Score = %d, want 4 (four matched rules)", result.Score)
	}

	// Unit-level: a written variable is reachable under any casing, and an
	// unknown name stays empty. Names are bare here — parseVarAction strips
	// the "tx." collection prefix before calling SetVar.
	tx := NewTransaction()
	tx.SetVar("critical_score", "5")
	if v := tx.GetVar("critical_score"); v != "5" {
		t.Fatalf("GetVar(critical_score) = %q, want %q", v, "5")
	}
	if v := tx.GetVar("CRITICAL_SCORE"); v != "5" {
		t.Fatalf("GetVar(CRITICAL_SCORE) = %q, want %q", v, "5")
	}
	if v := tx.GetVar("Critical_Score"); v != "5" {
		t.Fatalf("GetVar(Critical_Score) = %q, want %q", v, "5")
	}
	if v := tx.GetVar("nonexistent"); v != "" {
		t.Fatalf("GetVar(nonexistent) = %q, want empty", v)
	}
}

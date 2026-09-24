package crs

// Regression (round 2026-09-24-r9-tx-count-regex): the Resolve TX branch
// ignored rv.Count and rv.KeyRegex — "&TX:key" returned the key's VALUE
// instead of a count, "TX:/re/" looked the regex pattern up as a literal key
// name (always empty — every regex-selected TX rule went inert), "&TX:/re/"
// combined both defects, and "&TX" returned all values instead of the
// collection size. parseVariables is collection-agnostic and preserves
// Count+KeyRegex for TX exactly as for ARGS/HEADERS/COOKIES, whose count and
// regex branches were fixed by earlier rounds; TX was never covered.
// ModSecurity contract: &COLLECTION:key counts that key, &COLLECTION:/re/
// counts values across matching keys, &COLLECTION counts the collection, and
// COLLECTION:/re/ selects matching keys' values. Empty-valued TX variables
// count as absent, mirroring the pinned value form (TX:empty_var -> empty).

import (
	"testing"
)

func TestResolve_TX_CountAndRegexForms(t *testing.T) {
	p := NewParser()
	parseOne := func(s string) RuleVariable {
		t.Helper()
		vars, err := p.parseVariables(s)
		if err != nil || len(vars) != 1 {
			t.Fatalf("parseVariables(%q) = %v, %v", s, vars, err)
		}
		return vars[0]
	}

	tx := NewTransaction()
	tx.SetVar("anomaly_score", "5")
	tx.SetVar("sql_error_1", "You have an error in your SQL syntax")
	tx.SetVar("sql_error_2", "mysql_fetch_array(): supplied argument")
	vr := NewVariableResolver(tx)

	// Count form, exact key: &TX:anomaly_score counts (1), not the value ("5").
	vals, err := vr.Resolve(parseOne("&TX:anomaly_score"))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "1" {
		t.Fatalf("&TX:anomaly_score = %v, want [\"1\"]", vals)
	}

	// Regex selection, value form: TX:/sql_error_/ selects matching values.
	vals, err = vr.Resolve(parseOne("TX:/sql_error_/"))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 2 {
		t.Fatalf("TX:/sql_error_/ = %v, want the 2 matching values", vals)
	}

	// Count + regex: &TX:/sql_error_/ counts matching variables.
	vals, err = vr.Resolve(parseOne("&TX:/sql_error_/"))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "2" {
		t.Fatalf("&TX:/sql_error_/ = %v, want [\"2\"]", vals)
	}

	// Keyless count: &TX is the collection size.
	vals, err = vr.Resolve(parseOne("&TX"))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "3" {
		t.Fatalf("&TX = %v, want [\"3\"]", vals)
	}

	// Count of a missing key.
	vals, err = vr.Resolve(parseOne("&TX:nonexistent"))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "0" {
		t.Fatalf("&TX:nonexistent = %v, want [\"0\"]", vals)
	}

	// Empty-valued variables count as absent (mirrors the value-form pin).
	tx.SetVar("empty_var", "")
	vals, err = vr.Resolve(parseOne("&TX:empty_var"))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "0" {
		t.Fatalf("&TX:empty_var = %v, want [\"0\"]", vals)
	}

	// Controls: the pinned value forms are unchanged.
	vals, err = vr.Resolve(parseOne("TX:anomaly_score"))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "5" {
		t.Fatalf("TX:anomaly_score = %v, want [\"5\"]", vals)
	}
	vals, err = vr.Resolve(parseOne("TX:nonexistent"))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 0 {
		t.Fatalf("TX:nonexistent = %v, want empty", vals)
	}
	vals, err = vr.Resolve(RuleVariable{Name: "TX", Key: "empty_var"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 0 {
		t.Fatalf("TX:empty_var = %v, want empty", vals)
	}
}

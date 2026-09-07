package crs

import "testing"

// Regression: resolveArgs' count path returned len(RequestArgs) — the number
// of distinct KEYS — while ModSecurity &ARGS counts every name=value pair.
// Parameter pollution (repeated parameter names) therefore undercounted and
// count-based CRS rules could miss it. The count must mirror resolveHeaders'
// total-value counting.
func TestResolveArgsCountCountsAllValues(t *testing.T) {
	tx := NewTransaction()
	tx.RequestArgs = map[string][]string{
		"a": {"1", "2"}, // repeated parameter name — pollution
		"b": {"3"},
	}
	resolver := NewVariableResolver(tx)

	vals, err := resolver.Resolve(RuleVariable{Name: "ARGS", Count: true})
	if err != nil {
		t.Fatalf("Resolve(ARGS, count): %v", err)
	}
	if len(vals) != 1 || vals[0] != "3" {
		t.Fatalf("FAIL: &ARGS count = %v, want [3] (every name=value pair counts)", vals)
	}
}

// Control: with only single-valued keys, the total equals the key count.
func TestResolveArgsCountSingleValueKeys(t *testing.T) {
	tx := NewTransaction()
	tx.RequestArgs = map[string][]string{
		"a": {"1"},
		"b": {"2"},
		"c": {"3"},
	}
	resolver := NewVariableResolver(tx)

	vals, err := resolver.Resolve(RuleVariable{Name: "ARGS", Count: true})
	if err != nil {
		t.Fatalf("Resolve(ARGS, count): %v", err)
	}
	if len(vals) != 1 || vals[0] != "3" {
		t.Fatalf("FAIL: &ARGS count = %v, want [3]", vals)
	}
}

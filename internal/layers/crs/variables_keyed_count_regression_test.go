package crs

import (
	"testing"
)

// Regression (round 2026-09-16): the count branches of resolveArgs,
// resolveHeaders, and resolveCookies ran before key handling and ignored the
// key entirely, so &ARGS:password, &ARGS:/re/, &REQUEST_HEADERS:Content-Length,
// and &REQUEST_COOKIES:session all returned the WHOLE-collection count
// instead of the keyed count. ModSecurity semantics: &COLLECTION:key counts
// that key's values and &COLLECTION:/re/ counts values across matching keys —
// the parameter-pollution detection idiom (SecRule &ARGS:password "@eq 2").
// parseVariables preserves Key/KeyRegex together with Count, so keyed count
// rules resolve through this path. Keyless totals keep the round-23
// total-value semantics (see variables_args_count_test.go).

func TestResolve_KeyedArgsCountCountsOnlyThatKey(t *testing.T) {
	tx := NewTransaction()
	tx.RequestArgs = map[string][]string{
		"password": {"1", "2"}, // duplicate password params — HPP
		"x":        {"3"},
	}
	resolver := NewVariableResolver(tx)

	vals, err := resolver.Resolve(RuleVariable{Collection: "ARGS", Key: "password", Count: true})
	if err != nil {
		t.Fatalf("Resolve(&ARGS:password): %v", err)
	}
	if len(vals) != 1 || vals[0] != "2" {
		t.Fatalf("&ARGS:password count = %v, want [2]", vals)
	}

	// Keyless &ARGS keeps the total-value semantics.
	vals, err = resolver.Resolve(RuleVariable{Collection: "ARGS", Count: true})
	if err != nil {
		t.Fatalf("Resolve(&ARGS): %v", err)
	}
	if len(vals) != 1 || vals[0] != "3" {
		t.Fatalf("keyless &ARGS count = %v, want [3]", vals)
	}
}

func TestResolve_KeyedRegexArgsCountCountsMatchingKeys(t *testing.T) {
	tx := NewTransaction()
	tx.RequestArgs = map[string][]string{
		"user_1": {"a"},
		"user_2": {"b"},
		"other":  {"c"},
	}
	resolver := NewVariableResolver(tx)

	vals, err := resolver.Resolve(RuleVariable{Collection: "ARGS", Key: "^user_", KeyRegex: true, Count: true})
	if err != nil {
		t.Fatalf("Resolve(&ARGS:/^user_/): %v", err)
	}
	if len(vals) != 1 || vals[0] != "2" {
		t.Fatalf("&ARGS:/^user_/ count = %v, want [2]", vals)
	}
}

func TestResolve_KeyedHeaderAndCookieCounts(t *testing.T) {
	tx := NewTransaction()
	tx.RequestHeaders = map[string][]string{
		"Content-Length": {"5"},
		"Accept":         {"*/*"},
	}
	tx.RequestCookies = map[string]string{
		"session": "s",
		"theme":   "dark",
	}
	resolver := NewVariableResolver(tx)

	vals, err := resolver.Resolve(RuleVariable{Collection: "REQUEST_HEADERS", Key: "Content-Length", Count: true})
	if err != nil {
		t.Fatalf("Resolve(&REQUEST_HEADERS:Content-Length): %v", err)
	}
	if len(vals) != 1 || vals[0] != "1" {
		t.Fatalf("&REQUEST_HEADERS:Content-Length count = %v, want [1]", vals)
	}

	vals, err = resolver.Resolve(RuleVariable{Collection: "REQUEST_COOKIES", Key: "session", Count: true})
	if err != nil {
		t.Fatalf("Resolve(&REQUEST_COOKIES:session): %v", err)
	}
	if len(vals) != 1 || vals[0] != "1" {
		t.Fatalf("&REQUEST_COOKIES:session count = %v, want [1]", vals)
	}

	// Keyless totals unchanged.
	vals, err = resolver.Resolve(RuleVariable{Collection: "REQUEST_HEADERS", Count: true})
	if err != nil {
		t.Fatalf("Resolve(&REQUEST_HEADERS): %v", err)
	}
	if len(vals) != 1 || vals[0] != "2" {
		t.Fatalf("keyless &REQUEST_HEADERS count = %v, want [2]", vals)
	}
	vals, err = resolver.Resolve(RuleVariable{Collection: "REQUEST_COOKIES", Count: true})
	if err != nil {
		t.Fatalf("Resolve(&REQUEST_COOKIES): %v", err)
	}
	if len(vals) != 1 || vals[0] != "2" {
		t.Fatalf("keyless &REQUEST_COOKIES count = %v, want [2]", vals)
	}
}

// Control: a keyed NON-count resolution (plain ARGS:password) is unaffected —
// only the count path was corrupted.
func TestResolve_KeyedNonCountResolutionUnaffected(t *testing.T) {
	tx := NewTransaction()
	tx.RequestArgs = map[string][]string{
		"password": {"1", "2"},
		"x":        {"3"},
	}
	resolver := NewVariableResolver(tx)

	vals, err := resolver.Resolve(RuleVariable{Collection: "ARGS", Key: "password"})
	if err != nil {
		t.Fatalf("Resolve(ARGS:password): %v", err)
	}
	if len(vals) != 2 || vals[0] != "1" || vals[1] != "2" {
		t.Fatalf("keyed non-count resolution = %v, want [1 2]", vals)
	}
}

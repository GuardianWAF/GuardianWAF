package graphql

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (hunt round 10/25): countAliases tokenized ANY "ident : ident"
// pair anywhere in the query — including inside parentheses — so variable
// definitions ($limit: Int) and field arguments (status: published) each
// counted as "aliases" (55-pt Medium finding → blocked at the ≥50 line),
// while the true-positive side required the colon IMMEDIATELY after the
// ident, so the legal form "alias : field" (whitespace before the colon)
// evaded the check entirely.

func aliasAbuseFinding(res engine.LayerResult) *engine.Finding {
	for i := range res.Findings {
		if res.Findings[i].Category == "graphql-aliasing-abuse" {
			return &res.Findings[i]
		}
	}
	return nil
}

func runGraphQLDetector(t *testing.T, query string) engine.LayerResult {
	t.Helper()
	d := NewDetector(true, 1.0, 100, 1000, false, nil)
	r := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("Content-Type", "application/json")
	ctx := engine.AcquireContext(r, 1, 1<<20)
	defer engine.ReleaseContext(ctx)
	ctx.BodyString = fmt.Sprintf(`{"query": %q}`, query)
	return d.Process(ctx)
}

// Eleven variable definitions are ordinary pagination/filter parameters, but
// each "$name: Type" pair was counted as an alias → legitimate queries were
// blocked with a 55-point aliasing-abuse finding.
func TestVariableDefinitionsAreNotAliases(t *testing.T) {
	vars := make([]string, 0, 11)
	for _, v := range []string{"limit", "offset", "filter", "sort", "dir", "after", "before", "first", "last", "q", "id"} {
		vars = append(vars, "$"+v+": String")
	}
	query := "query Q(" + strings.Join(vars, ", ") + ") { users }"
	res := runGraphQLDetector(t, query)
	if f := aliasAbuseFinding(res); f != nil {
		t.Fatalf("FAIL: a query with 11 variable definitions was flagged as aliasing abuse (score %d) — variable definitions are not aliases", f.Score)
	}
}

// Enum-valued field arguments are ordinary query parameters, but each
// "arg: value" pair inside (...) was counted as an alias.
func TestFieldArgumentsAreNotAliases(t *testing.T) {
	pairs := make([]string, 0, 11)
	for _, a := range []string{"status", "tag", "sort", "dir", "lang", "view", "mode", "kind", "tier", "state", "format"} {
		pairs = append(pairs, a+": "+a[:3])
	}
	query := "{ posts(" + strings.Join(pairs, ", ") + ") { id } }"
	res := runGraphQLDetector(t, query)
	if f := aliasAbuseFinding(res); f != nil {
		t.Fatalf("FAIL: a query with 11 enum-valued field arguments was flagged as aliasing abuse (score %d) — arguments are not aliases", f.Score)
	}
}

// "alias : field" is legal GraphQL (whitespace between tokens). The aliasing
// cost attack must not be evadable by that formatting.
func TestWhitespaceSeparatedAliasesStillCounted(t *testing.T) {
	var pairs []string
	for i := 1; i <= 11; i++ {
		pairs = append(pairs, fmt.Sprintf("a%d : f%d", i, i))
	}
	query := "{ " + strings.Join(pairs, " ") + " }"
	res := runGraphQLDetector(t, query)
	if aliasAbuseFinding(res) == nil {
		t.Fatalf("FAIL: 11 'alias : field' pairs (whitespace before the colon, legal GraphQL) produced no aliasing-abuse finding — the cost check is evadable")
	}
}

// Control: the tight form must keep firing, before and after the fix.
func TestTightAliasesStillCounted(t *testing.T) {
	var pairs []string
	for i := 1; i <= 11; i++ {
		pairs = append(pairs, fmt.Sprintf("a%d:f%d", i, i))
	}
	query := "{ " + strings.Join(pairs, " ") + " }"
	res := runGraphQLDetector(t, query)
	if aliasAbuseFinding(res) == nil {
		t.Fatalf("FAIL: 11 tight aliases produced no aliasing-abuse finding — true positives lost")
	}
}

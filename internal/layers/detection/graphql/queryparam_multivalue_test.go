package graphql

import (
	"net/url"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (2026-09-15 round): extractQueries analyzed ONLY rawQ[0] of the
// ?query= parameter. Repeated parameters are legal and backends parse
// first-wins OR last-wins (implementation-dependent), so the unanalyzed
// value carried the payload: a depth-41 bomb in the second value produced
// zero findings. Additionally, Process derived the batch count from
// len(queries), conflating transport SOURCES with operations — `?query=X`
// plus a single-op JSON body fired the 70-point batch-query-bomb finding
// although any backend executes exactly one query.
func TestProcess_AnalyzesEveryQueryParamValue(t *testing.T) {
	det := NewDetector(true, 1.0, 10, 1000, false, []string{"/graphql"})
	deep := `{` + strings.Repeat("a{", 40) + "x" + strings.Repeat("}", 40) + `}`

	// Benign first, bomb second (last-wins backends execute the bomb).
	res := det.Process(makeCtx("", "/graphql", "query=ping&query="+url.QueryEscape(deep), ""))
	if !findingHasCategory(res.Findings, "graphql-depth-exceeded") {
		t.Fatalf("depth bomb in the second ?query= value not detected (score=%d findings=%v)", res.Score, res.Findings)
	}

	// Bomb first, benign second (first-wins backends see the bomb).
	res = det.Process(makeCtx("", "/graphql", "query="+url.QueryEscape(deep)+"&query=ping", ""))
	if !findingHasCategory(res.Findings, "graphql-depth-exceeded") {
		t.Fatalf("depth bomb in the first ?query= value not detected (score=%d findings=%v)", res.Score, res.Findings)
	}
}

func TestProcess_ParamPlusSingleOpBodyIsNotABatch(t *testing.T) {
	det := NewDetector(true, 1.0, 10, 1000, false, []string{"/graphql"})
	res := det.Process(makeCtx("application/json", "/graphql", "query={user{name}}", `{"query":"{user{email}}"}`))
	if findingHasCategory(res.Findings, "graphql-batch-query-bomb") {
		t.Fatalf("query param + single-op JSON body must not be a batch bomb: %v", res.Findings)
	}
	if res.Score != 0 {
		t.Fatalf("score = %d, want 0 for a benign param + benign single-op body", res.Score)
	}
}

// A JSON-array body still counts its operations toward the batch finding,
// even alongside a query parameter.
func TestProcess_ParamPlusJSONArrayBodyStillBatch(t *testing.T) {
	det := NewDetector(true, 1.0, 10, 1000, false, []string{"/graphql"})
	res := det.Process(makeCtx("application/json", "/graphql", "query={user{name}}",
		`[{"query":"{a}"},{"query":"{b}"}]`))
	if !findingHasCategory(res.Findings, "graphql-batch-query-bomb") {
		t.Fatalf("JSON-array batch beside a query param must still be flagged: %v", res.Findings)
	}
}

func findingHasCategory(findings []engine.Finding, cat string) bool {
	for _, f := range findings {
		if f.Category == cat {
			return true
		}
	}
	return false
}

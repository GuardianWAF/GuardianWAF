package graphql

// Regression (round 2026-09-28-graphql-appgraphql-batch): the
// application/graphql branch funneled JSON bodies through
// tryExtractJSONQuery, whose batch branch returned ONLY batch[0]["query"].
// For Content-Type: application/graphql with a JSON-array body, operations
// >= 1 were never analyzed (depth/complexity/alias/introspection all blind)
// and batchOps stayed 0, so no batch finding fired — while the SAME bytes
// sent as application/json were fully handled. Violated the file's own
// contracts: "batchOps counts operations inside a JSON-array body" and the
// query-param fix principle "EVERY value must be analyzed ... only the
// attacker knows which value will execute". The branch now handles arrays
// with the same all-ops loop as the application/json branch.

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// deepBatchQuery is depth 8 (the shape pinned by TestDepthAttack_JSONWrapped
// for the JSON branch) against maxDepth 5.
const deepBatchQuery = `{u{f{u{f{u{f{u{f{name}}}}}}}}}`

func hasBatchCategory(res engine.LayerResult) bool {
	for _, f := range res.Findings {
		if f.Category == "graphql-batch-query-bomb" {
			return true
		}
	}
	return false
}

// Defect case 1: a depth payload in op >= 1 of an application/graphql batch
// array must be analyzed and scored, not silently dropped with op[0]'s result.
func TestAppGraphQLBatch_LaterOpDepthDetected(t *testing.T) {
	det := NewDetector(true, 1.0, 5, 1000, false, []string{"/graphql"})
	res := det.Process(makeCtx("application/graphql", "/graphql", "",
		`[{"query":"{a}"},{"query":"`+deepBatchQuery+`"}]`))
	if res.Score == 0 {
		t.Fatalf("FAIL: depth bomb in op[1] of an application/graphql batch produced score 0")
	}
}

// Defect case 2: batchOps must count application/graphql array operations,
// so multiple benign ops still fire the batch-query-bomb finding.
func TestAppGraphQLBatch_BatchCountFires(t *testing.T) {
	det := NewDetector(true, 1.0, 5, 1000, false, []string{"/graphql"})
	res := det.Process(makeCtx("application/graphql", "/graphql", "",
		`[{"query":"{a}"},{"query":"{b}"},{"query":"{c}"},{"query":"{d}"}]`))
	if !hasBatchCategory(res) {
		t.Fatalf("FAIL: 4-op application/graphql batch produced no batch-query-bomb finding, got %+v", res.Findings)
	}
}

// Control: the application/json batch branch keeps its established behavior
// (the same body must stay detected via the JSON transport).
func TestAppGraphQLBatch_JSONTransportControl(t *testing.T) {
	det := NewDetector(true, 1.0, 5, 1000, false, []string{"/graphql"})
	res := det.Process(makeCtx("application/json", "/graphql", "",
		`[{"query":"{a}"},{"query":"`+deepBatchQuery+`"}]`))
	if res.Score == 0 {
		t.Fatalf("FAIL: JSON-transport batch with deep op[1] scored 0 (control broken)")
	}
}

// Control: the single-op object form under application/graphql keeps working
// through tryExtractJSONQuery after the batch branch was removed from it.
func TestAppGraphQLBatch_SingleOpObjectControl(t *testing.T) {
	det := NewDetector(true, 1.0, 5, 1000, false, []string{"/graphql"})
	res := det.Process(makeCtx("application/graphql", "/graphql", "",
		`{"query":"`+deepBatchQuery+`"}`))
	if res.Score == 0 {
		t.Fatalf("FAIL: single-op object under application/graphql scored 0 (control broken)")
	}
}

// Boundary: a benign single-op object stays clean (no false positive from the
// new array handling).
func TestAppGraphQLBatch_BenignObjectClean(t *testing.T) {
	det := NewDetector(true, 1.0, 5, 1000, false, []string{"/graphql"})
	res := det.Process(makeCtx("application/graphql", "/graphql", "",
		`{"query":"{a}"}`))
	if res.Score != 0 {
		t.Fatalf("FAIL: benign single-op object scored %d, want 0", res.Score)
	}
}

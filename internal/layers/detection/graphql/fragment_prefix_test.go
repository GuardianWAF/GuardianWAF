package graphql

import (
	"strconv"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (2026-09-15 round): the fragment-keyword check in
// parseFragmentGraph verified only the LEFT boundary (the character before
// "fragment" must not continue an identifier) and never the RIGHT boundary,
// so any token beginning with "fragment" — e.g. the legal alias
// fragmentInfo — was mis-parsed as the keyword with a phantom name. The
// alias's selection set then became a phantom fragment body: its spreads
// were attributed to a name colliding with (overwriting) the real
// definition's adjacency, manufacturing a fragment cycle (85/High, blocked
// at the >= 50 threshold) in fully valid GraphQL.
func TestDetect_FragmentPrefixedAlias_NoPhantomCycle(t *testing.T) {
	det := NewDetector(true, 1.0, 50, 10000, false, nil)
	valid := `fragment Info on Node { id }
query { fragmentInfo: node { ...F } }
fragment F on Node { ...Info }`
	res := det.Process(&engine.RequestContext{
		Path:           "/graphql",
		NormalizedPath: "/graphql",
		ContentType:    "application/json",
		BodyString:     `{"query":` + strconv.Quote(valid) + `}`,
	})
	for _, f := range res.Findings {
		if strings.Contains(f.Description, "fragment cycle") {
			t.Fatalf("FAIL: valid query with a fragment-prefixed alias flagged as a fragment cycle: %+v", res.Findings)
		}
	}
	if res.Score != 0 {
		t.Fatalf("FAIL: score = %d, want 0 for a benign valid query", res.Score)
	}
}

// The right boundary requires a non-identifier after the keyword: GraphQL
// whitespace (including newlines) between "fragment" and the name keeps the
// keyword matching, so cycled fragments separated by newlines stay detected —
// and the parseFragmentGraph-level phantom must not reappear.
func TestParseFragmentGraph_FragmentKeywordRightBoundary(t *testing.T) {
	if !detectFragmentCycle("fragment\nA on T { ...B } fragment\nB on T { ...A }") {
		t.Fatal("FAIL: newline-separated fragment keyword no longer matches (right boundary too strict)")
	}
	if !detectFragmentCycle("fragment A on User { ...B } fragment B on User { ...A }") {
		t.Fatal("FAIL: real two-node cycle no longer detected")
	}
	if detectFragmentCycle(`fragment Info on Node { id }
query { fragmentInfo: node { ...F } }
fragment F on Node { ...Info }`) {
		t.Fatal("FAIL: fragment-prefixed alias still manufactures a cycle at the parseFragmentGraph level")
	}
}

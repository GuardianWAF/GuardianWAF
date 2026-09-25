package virtualpatch

// Regression (round 2026-09-25-r3-virtualpatch-uri-encoding): getValueByType's
// "uri" scope matched ONLY ctx.Request.URL.RequestURI() — the raw,
// still-percent-encoded path+query (the deliberately-deferred sibling of the
// r17 query-scope fix). The attacker selects the encoding of the same payload:
// "class.module" rides in the path as "class%2Emodule" (and in the query as
// x=class%2Emodule), so an operator-authored uri-scoped contains-patch never
// fired on the encoded form of the identical request. Post-fix the "uri"
// scope also returns the decoded path (URL.Path) and the engine's decoded
// query values (ctx.QueryParams keys and values); the any-match loop in
// matchPattern inspects every returned value (the round-20 multi-value
// family, extended to representations).

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func uriEncodingLayer() *Layer {
	layer := NewLayer(&Config{Enabled: true, BlockSeverity: []string{"CRITICAL"}})
	layer.AddPatch(&VirtualPatch{
		ID:          "VP-URI-ENC-001",
		Name:        "uri-scope encoded-payload guard",
		Description: "regression: uri scope must see the decoded path and query",
		GeneratedAt: time.Now(),
		Patterns: []PatchPattern{
			{Type: "uri", Pattern: "class.module", MatchType: "contains"},
		},
		Action:     "block",
		Score:      50,
		Severity:   "CRITICAL",
		MatchLogic: "or",
		Enabled:    true,
	})
	return layer
}

func TestURIScopedPatchesSeeEncodedPayloads(t *testing.T) {
	layer := uriEncodingLayer()

	// Control: the unencoded payload blocks through the real AcquireContext
	// population path.
	plain := httptest.NewRequest("GET", "http://target/class.module.classLoader=attack", nil)
	if res := layer.Process(engine.AcquireContext(plain, 1, 1<<20)); res.Action != engine.ActionBlock {
		t.Fatalf("control: unencoded class.module path payload did not block: action=%v", res.Action)
	}

	// The fixed defect (path portion): the SAME payload with the dot
	// percent-encoded.
	encodedPath := httptest.NewRequest("GET", "http://target/class%2Emodule.classLoader=attack", nil)
	if res := layer.Process(engine.AcquireContext(encodedPath, 1, 1<<20)); res.Action != engine.ActionBlock {
		t.Fatalf("percent-encoded class.module path payload evaded the uri-scoped patch: action=%v", res.Action)
	}

	// The fixed defect (query portion observed through the uri scope).
	encodedQuery := httptest.NewRequest("GET", "http://target/?x=class%2Emodule", nil)
	if res := layer.Process(engine.AcquireContext(encodedQuery, 1, 1<<20)); res.Action != engine.ActionBlock {
		t.Fatalf("percent-encoded class.module query payload evaded the uri-scoped patch: action=%v", res.Action)
	}
}

// Clean traffic must not block: the decoded-representation widening must not
// invent matches that the raw URI never contained.
func TestURIScopedPatchDoesNotBlockCleanTraffic(t *testing.T) {
	layer := uriEncodingLayer()
	clean := httptest.NewRequest("GET", "http://target/products/42?page=2&sort=price", nil)
	if res := layer.Process(engine.AcquireContext(clean, 1, 1<<20)); res.Action == engine.ActionBlock {
		t.Fatalf("clean traffic blocked by the uri-scoped patch: action=%v", res.Action)
	}
}

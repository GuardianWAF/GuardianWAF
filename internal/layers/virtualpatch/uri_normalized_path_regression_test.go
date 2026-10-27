package virtualpatch

// Regression (round 2026-10-13-r5-uri-normalized-path): the r3 uri-scope fix
// extended getValueByType's "uri" case to the decoded representations
// (RequestURI + URL.Path + QueryParams), but URL.Path still carries the
// wire's redundant segments. An operator-authored uri-scoped contains-patch
// written against the canonical route was therefore bypassed by
// segment-normalized traversal variants of the identical request —
// /wp-json//wp/v1/users, /wp-json/./wp/v1/users, /wp-json/x/../wp/v1/users —
// whose raw and decoded forms both miss the pattern while the backend
// resolves exactly the canonical route (the r40 path-scope reasoning, which
// the path scope already implements via NormalizedPath). Post-fix the "uri"
// scope also returns ctx.NormalizedPath when the sanitizer has produced it.
//
// The population path is part of the defect surface: ctx.NormalizedPath is
// populated by the sanitizer (order 300) before this layer runs (order 450),
// so the harness runs the REAL sanitizer layer on the AcquireContext result —
// not hand-built literals.

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/sanitizer"
)

func uriNormalizedLayer() *Layer {
	layer := NewLayer(&Config{Enabled: true, BlockSeverity: []string{"CRITICAL"}})
	layer.AddPatch(&VirtualPatch{
		ID:          "VP-URI-NORM-001",
		Name:        "uri-scope segment-normalization guard",
		Description: "regression: uri scope must see the sanitizer-canonicalized route",
		GeneratedAt: time.Now(),
		Patterns: []PatchPattern{
			{Type: "uri", Pattern: "/wp-json/wp/v1/users", MatchType: "contains"},
		},
		Action:     "block",
		Score:      50,
		Severity:   "CRITICAL",
		MatchLogic: "or",
		Enabled:    true,
	})
	return layer
}

// runPipelineToVirtualPatch mirrors the production order: AcquireContext →
// sanitizer (order 300) → virtualpatch (order 450). sanitizer argument nil
// skips the sanitizer (the boundary case where NormalizedPath stays empty).
func runPipelineToVirtualPatch(layer *Layer, san *sanitizer.Layer, target string) engine.LayerResult {
	req := httptest.NewRequest("GET", target, nil)
	ctx := engine.AcquireContext(req, 1, 1<<20)
	defer engine.ReleaseContext(ctx)
	if san != nil {
		_ = san.Process(ctx)
	}
	return layer.Process(ctx)
}

func TestURIScopedPatchesSeeSegmentNormalizedRoutes(t *testing.T) {
	layer := uriNormalizedLayer()
	san := sanitizer.NewLayer(&sanitizer.Config{})

	// Control: the canonical route blocks, before and after the fix.
	if res := runPipelineToVirtualPatch(layer, san, "http://target/wp-json/wp/v1/users"); res.Action != engine.ActionBlock {
		t.Fatalf("control: canonical route did not block: action=%v", res.Action)
	}

	// The fixed defect: traversal variants the backend resolves to the very
	// same route. Raw and decoded forms both miss the pattern; only the
	// NormalizedPath representation sees through the redundant segments.
	for _, variant := range []string{
		"http://target/wp-json//wp/v1/users",
		"http://target/wp-json/./wp/v1/users",
		"http://target/wp-json/x/../wp/v1/users",
	} {
		if res := runPipelineToVirtualPatch(layer, san, variant); res.Action != engine.ActionBlock {
			t.Fatalf("segment-normalized traversal %s evaded the uri-scoped patch: action=%v", variant, res.Action)
		}
	}

	// Clean traffic must not block: the widening only adds the canonical form
	// of the route that was actually requested.
	if res := runPipelineToVirtualPatch(layer, san, "http://target/products/42?page=2"); res.Action == engine.ActionBlock {
		t.Fatalf("clean traffic blocked by the uri-scoped patch: action=%v", res.Action)
	}
}

// Without the sanitizer run (NormalizedPath empty), the uri scope keeps its
// historical behavior exactly: the widening must not invent values that were
// never populated.
func TestURIScopedWideningRequiresSanitizerNormalization(t *testing.T) {
	layer := uriNormalizedLayer()

	// The encoding family still holds without the sanitizer: the canonical
	// route itself is in RequestURI/URL.Path, so it blocks as before.
	if res := runPipelineToVirtualPatch(layer, nil, "http://target/wp-json/wp/v1/users"); res.Action != engine.ActionBlock {
		t.Fatalf("control: canonical route did not block without sanitizer: action=%v", res.Action)
	}

	// The traversal variant passes when nothing populated NormalizedPath —
	// pinning that the widened value comes from the sanitizer, not thin air.
	if res := runPipelineToVirtualPatch(layer, nil, "http://target/wp-json//wp/v1/users"); res.Action == engine.ActionBlock {
		t.Fatalf("traversal blocked although no sanitizer populated NormalizedPath: action=%v", res.Action)
	}
}

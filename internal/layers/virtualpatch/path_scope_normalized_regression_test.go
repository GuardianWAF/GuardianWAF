package virtualpatch

// Regression test: the "path" pattern scope must match the sanitizer-normalized
// path, not only the raw wire path.
//
// getValueByType's "path" case returned []string{ctx.Path} — the single raw
// representation. The sanitizer (order 300) also populates ctx.NormalizedPath,
// the route the backend actually resolves (CanonicalizePath collapses "//", "."
// and ".." segments). A request whose raw path reaches a declared route only
// through traversal segments therefore slipped past every path-scoped virtual
// patch: /api/../wp-json/wp/v1/users has a raw path that fails a ^-anchored
// regex while its normalized form is exactly the declared target.
//
// This is the NormalizedPath||Path dual view every other path-consuming surface
// already uses (lfi/ssrf/cmdi/ssti/nosqli, xss/sqli, ratelimit, apisecurity)
// and the same representation reasoning the "query"/"uri" scopes apply. The
// shipped VP-WP-REST-001 patch ("^/wp-json/wp/v[0-9]+/users") was reachable
// around; the cases below drive the real engine.AcquireContext -> sanitizer ->
// virtualpatch production path.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/sanitizer"
)

// vpPathPipelineResult runs the production layers in pipeline order
// (sanitizer order 300 -> virtualpatch order 450) over a real request.
func vpPathPipelineResult(t *testing.T, target string) engine.LayerResult {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.RemoteAddr = "203.0.113.10:54321"

	ctx := engine.AcquireContext(req, 0, 1<<20)
	defer engine.ReleaseContext(ctx)

	sanitizer.NewLayer(&sanitizer.Config{}).Process(ctx)
	return NewLayer(&Config{Enabled: true, BlockSeverity: []string{"HIGH"}}).Process(ctx)
}

// wpPatchFired reports whether the shipped WordPress patch (CVE-2017-1001000)
// matched.
func wpPatchFired(res engine.LayerResult) bool {
	for _, f := range res.Findings {
		if f.Category == "CVE-2017-1001000" {
			return true
		}
	}
	return false
}

// A traversal-encoded request to the declared route must still be matched.
func TestVirtualPatchPathScopeMatchesNormalizedPath(t *testing.T) {
	for _, target := range []string{
		"/api/../wp-json/wp/v1/users",
		"/wp-json/./wp/v1/users",
		"//wp-json/wp/v1/users",
	} {
		t.Run(target, func(t *testing.T) {
			res := vpPathPipelineResult(t, target)
			if !wpPatchFired(res) {
				t.Fatalf("path-scoped patch did not fire for %q (action=%v, score=%d, findings=%d): the normalized path is the route the backend resolves, so the patch must match it",
					target, res.Action, res.Score, len(res.Findings))
			}
		})
	}
}

// The canonical form of the same route must keep matching — the fix must not
// trade one representation for another.
func TestVirtualPatchPathScopeCanonicalPathStillMatches(t *testing.T) {
	res := vpPathPipelineResult(t, "/wp-json/wp/v1/users")
	if !wpPatchFired(res) {
		t.Fatalf("canonical path /wp-json/wp/v1/users must match the shipped patch (action=%v, findings=%d)",
			res.Action, len(res.Findings))
	}
}

// An unrelated path must still pass: the dual view must not broaden the
// matcher into a false positive.
func TestVirtualPatchPathScopeUnrelatedPathStillPasses(t *testing.T) {
	for _, target := range []string{"/healthz", "/api/v1/users", "/wp-admin/"} {
		t.Run(target, func(t *testing.T) {
			res := vpPathPipelineResult(t, target)
			if res.Action != engine.ActionPass || wpPatchFired(res) {
				t.Fatalf("unrelated path %q must pass untouched (action=%v, patchFired=%v)",
					target, res.Action, wpPatchFired(res))
			}
		})
	}
}

// A path-scoped operator patch written against the decoded form must fire on
// the raw wire form too (both representations are inspected).
func TestVirtualPatchPathScopeInspectsBothRepresentations(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true, BlockSeverity: []string{"CRITICAL"}})
	layer.AddPatch(&VirtualPatch{
		ID:       "VP-TEST-PATH-DUALVIEW",
		Name:     "operator path patch",
		Enabled:  true,
		Action:   "block",
		Score:    50,
		Severity: "CRITICAL",
		Patterns: []PatchPattern{
			{Type: "path", Pattern: "/restricted", MatchType: "contains"},
		},
		MatchLogic: "or",
	})

	req := httptest.NewRequest(http.MethodGet, "/public/../restricted", nil)
	req.RemoteAddr = "203.0.113.10:54321"
	ctx := engine.AcquireContext(req, 0, 1<<20)
	defer engine.ReleaseContext(ctx)
	sanitizer.NewLayer(&sanitizer.Config{}).Process(ctx)

	res := layer.Process(ctx)
	if res.Action != engine.ActionBlock {
		t.Fatalf("operator path patch must fire for the traversal form of /restricted (action=%v, score=%d)",
			res.Action, res.Score)
	}
}

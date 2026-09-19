package openredirect

// Regression (bug-hunt round 2026-09-18-r8): Process checked BOTH query
// forms — ctx.QueryParams ("query:"+param) and ctx.NormalizedQuery
// ("nquery:"+param) — with no shared dedup, while every sibling detector
// (lfi, cmdi, xss, and sqli since round-2026-09-18-r7) documents and
// implements "identical strings are scanned once (dedup) so unchanged inputs
// aren't double-counted". When the sanitizer leaves a redirect param value
// unchanged — the common case — the same attack value was checked twice and
// produced TWO additive findings ("query:next" + "nquery:next"), doubling the
// score (60 → 120) and spuriously pushing requests past the block threshold.

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// TestOpenRedirectIdenticalFormsDetectedOnce is the defect case: the same
// (param, value) pair in both query forms must be checked exactly once.
func TestOpenRedirectIdenticalFormsDetectedOnce(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := &engine.RequestContext{
		Method:         "GET",
		Path:           "/login",
		NormalizedPath: "/login",
		QueryParams:    map[string][]string{"next": {"//evil.com/path"}},
		NormalizedQuery: map[string][]string{
			"next": {"//evil.com/path"}, // sanitizer left the value unchanged
		},
		Headers: map[string][]string{"Host": {"app.example.com"}},
	}

	result := d.Process(ctx)
	if len(result.Findings) != 1 {
		t.Fatalf("FAIL: an unchanged redirect value in both query forms produced %d findings (score %d) — identical (param, value) pairs must be checked once; got %+v", len(result.Findings), result.Score, result.Findings)
	}
}

// Control: genuinely divergent forms are BOTH checked — dedup must only
// collapse identical (param, value) pairs, not distinct views.
func TestOpenRedirectDivergentFormsBothChecked(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := &engine.RequestContext{
		Method:         "GET",
		Path:           "/login",
		NormalizedPath: "/login",
		QueryParams:    map[string][]string{"next": {"//evil.com/a"}},
		NormalizedQuery: map[string][]string{
			"next": {"https://evil.org/b"}, // sanitizer rewrote: distinct view
		},
		Headers: map[string][]string{"Host": {"app.example.com"}},
	}

	result := d.Process(ctx)
	if len(result.Findings) != 2 {
		t.Fatalf("FAIL: harness control — two divergent views must each be checked, got %d findings", len(result.Findings))
	}
}

// Control: a conforming same-origin redirect produces no findings.
func TestOpenRedirectConformingInputPasses(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := &engine.RequestContext{
		Method:         "GET",
		Path:           "/login",
		NormalizedPath: "/login",
		QueryParams:    map[string][]string{"next": {"/settings"}},
		NormalizedQuery: map[string][]string{
			"next": {"/settings"},
		},
		Headers: map[string][]string{"Host": {"app.example.com"}},
	}

	result := d.Process(ctx)
	if len(result.Findings) != 0 {
		t.Fatalf("FAIL: harness control — a conforming same-origin redirect must produce no findings, got %+v", result.Findings)
	}
}

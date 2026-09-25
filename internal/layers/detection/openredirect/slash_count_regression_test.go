package openredirect

import (
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (round 2026-09-25-round2-openredirect-slashrun): the scheme
// gate in checkValue fired only for the ZERO-slash form ("https:evil.com").
// The ONE-slash and THREE-slash spellings — "https:/evil.com",
// "https:///evil.com" — parse in Go's url.Parse with an EMPTY Host (RFC
// 3986: only "://" creates an authority), so they fell through the
// same-host classification (which requires host != "") and scored 0,
// while every WHATWG browser normalizes any slash run after a special
// scheme to the two-slash authority form and redirects off-site. The gate
// now fires on every non-canonical slash count (≠ 2); the canonical
// two-slash form stays with the ordinary URL classification, and the
// pre-existing zero-slash behavior is pinned unchanged.

func slashRunDetected(t *testing.T, host string, params map[string][]string) bool {
	t.Helper()
	req := httptest.NewRequest("GET", "http://"+host+"/login", nil)
	ctx := &engine.RequestContext{
		Request:     req,
		QueryParams: params,
		Headers:     map[string][]string{},
	}
	res := NewDetector(true, 1.0).Process(ctx)
	return res.Score > 0
}

// Defect case: one slash after the scheme must be flagged as external.
func TestSlashCountSingleSlashFlagged(t *testing.T) {
	if !slashRunDetected(t, "app.legit.test", map[string][]string{"next": {"https:/evil.com"}}) {
		t.Fatalf("'https:/evil.com' scored 0 — browsers resolve it to https://evil.com (external)")
	}
}

// Defect case: three slashes after the scheme must be flagged as external.
func TestSlashCountTripleSlashFlagged(t *testing.T) {
	if !slashRunDetected(t, "app.legit.test", map[string][]string{"next": {"https:///evil.com"}}) {
		t.Fatalf("'https:///evil.com' scored 0 — browsers resolve it to https://evil.com (external)")
	}
}

// The backslash-normalized one-slash form reaches the same gate: after the
// backslash branch rewrites "\"→"/", "https:\evil.com" is "https:/evil.com".
func TestSlashCountBackslashSingleSlashFlagged(t *testing.T) {
	if !slashRunDetected(t, "app.legit.test", map[string][]string{"next": {"https:\\evil.com"}}) {
		t.Fatalf("'https:\\evil.com' scored 0 — browsers resolve it to https://evil.com (external)")
	}
}

// Pinned pre-existing behavior: the zero-slash form stays flagged.
func TestSlashCountZeroSlashStillFlagged(t *testing.T) {
	if !slashRunDetected(t, "app.legit.test", map[string][]string{"next": {"https:evil.com"}}) {
		t.Fatalf("zero-slash 'https:evil.com' must stay flagged")
	}
}

// Pinned pre-existing behavior: canonical external absolute stays flagged.
func TestSlashCountCanonicalExternalStillFlagged(t *testing.T) {
	if !slashRunDetected(t, "app.legit.test", map[string][]string{"next": {"https://evil.com"}}) {
		t.Fatalf("canonical 'https://evil.com' must stay flagged")
	}
}

// The canonical two-slash SAME-HOST absolute must stay clean — the fix must
// not swallow the ordinary URL classification.
func TestSlashCountSameHostCanonicalClean(t *testing.T) {
	if slashRunDetected(t, "app.legit.test", map[string][]string{"next": {"https://app.legit.test/path"}}) {
		t.Fatalf("same-host canonical absolute redirect must stay clean")
	}
}

// Relative paths stay clean.
func TestSlashCountRelativeClean(t *testing.T) {
	if slashRunDetected(t, "app.legit.test", map[string][]string{"next": {"/settings/profile"}}) {
		t.Fatalf("relative path must stay clean")
	}
}

// A bare scheme with no target ("https:") and an empty authority
// ("https://") are not redirect targets and stay clean.
func TestSlashCountBareSchemeClean(t *testing.T) {
	if slashRunDetected(t, "app.legit.test", map[string][]string{"next": {"https:", "https://"}}) {
		t.Fatalf("bare scheme with no target must stay clean")
	}
}

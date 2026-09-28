package sanitizer

// Regression (round 2026-09-28-sanitizer-deadknobs-wiring): the
// normalize_encoding and path_overrides config knobs existed on
// config.SanitizerConfig (mapped by the YAML seam, defaulted true in
// DefaultConfig) but sanitizer.Config had no such fields, so
// buildSanitizer dropped them — both knobs were silently dead in serve
// mode. NormalizeEncoding now gates Process Step 1 (false = raw
// passthrough of the Normalized* fields, never empty, per the round-30
// shared-detector-view lesson) and PathOverrides customises MaxBodySize
// per path prefix (longest prefix wins).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func gateCtx(t *testing.T, path, body string) *engine.RequestContext {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "http://example.com"+path, nil)
	ctx := engine.AcquireContext(r, 1, 1<<20)
	ctx.Path = path
	ctx.BodyString = body
	ctx.Body = []byte(body)
	return ctx
}

// Defect case 1: a path_overrides entry tightens max_body_size for the
// matching path prefix only.
func TestPathOverrideEnforcedOnMatchingPrefix(t *testing.T) {
	cfg := Config{
		MaxBodySize:       1000,
		SkipNormalization: false,
		PathOverrides: []PathOverride{
			{Path: "/upload", MaxBodySize: 100},
		},
	}
	layer := NewLayer(&cfg)
	body := strings.Repeat("A", 200)
	if res := layer.Process(gateCtx(t, "/upload/file", body)); len(res.Findings) == 0 {
		t.Fatal("FAIL: 200-byte body over the /upload override (100) produced no finding")
	}
	// The same body under the global limit elsewhere stays clean.
	if res := layer.Process(gateCtx(t, "/other", body)); len(res.Findings) != 0 {
		t.Fatalf("FAIL: body under the global limit flagged on /other: %+v", res.Findings)
	}
}

// Boundary: exactly-at-limit bodies do not trip the override (strict >).
func TestPathOverrideExactlyAtLimitClean(t *testing.T) {
	cfg := Config{
		MaxBodySize:       1000,
		SkipNormalization: false,
		PathOverrides: []PathOverride{
			{Path: "/upload", MaxBodySize: 4},
		},
	}
	if res := NewLayer(&cfg).Process(gateCtx(t, "/upload", "aaaa")); len(res.Findings) != 0 {
		t.Fatalf("FAIL: body exactly at the override limit flagged: %+v", res.Findings)
	}
}

// Longest matching prefix wins when two overrides match one path.
func TestPathOverrideLongestPrefixWins(t *testing.T) {
	cfg := Config{
		MaxBodySize:       1000,
		SkipNormalization: false,
		PathOverrides: []PathOverride{
			{Path: "/api", MaxBodySize: 1},
			{Path: "/api/v2", MaxBodySize: 500},
		},
	}
	layer := NewLayer(&cfg)
	// /api/v2/users matches /api (limit 1) and /api/v2 (limit 500):
	// the longest prefix must win, so a 10-byte body passes.
	if res := layer.Process(gateCtx(t, "/api/v2/users", "0123456789")); len(res.Findings) != 0 {
		t.Fatalf("FAIL: longest-prefix override not honored: %+v", res.Findings)
	}
	// /api/v1 matches only /api (limit 1): a 10-byte body must trip it.
	if res := layer.Process(gateCtx(t, "/api/v1/users", "0123456789")); len(res.Findings) == 0 {
		t.Fatal("FAIL: shorter-prefix override not enforced")
	}
}

// Defect case 2: normalize_encoding=false must pass the raw values through
// the Normalized* fields unchanged (raw passthrough, never empty).
func TestNormalizeGateFalseRawPassthrough(t *testing.T) {
	cfg := Config{SkipNormalization: true}
	layer := NewLayer(&cfg)
	ctx := gateCtx(t, "/a%2Fb", "%2E%2E%2Fetc%2Fpasswd")
	ctx.QueryParams = map[string][]string{"q": {"%41"}}
	layer.Process(ctx)
	if ctx.NormalizedBody != "%2E%2E%2Fetc%2Fpasswd" {
		t.Fatalf("FAIL: normalize_encoding=false decoded NormalizedBody to %q", ctx.NormalizedBody)
	}
	if ctx.NormalizedPath != "/a%2Fb" {
		t.Fatalf("FAIL: normalize_encoding=false decoded NormalizedPath to %q", ctx.NormalizedPath)
	}
	if got := ctx.NormalizedQuery["q"]; len(got) != 1 || got[0] != "%41" {
		t.Fatalf("FAIL: normalize_encoding=false altered NormalizedQuery: %v", got)
	}
	// Never-empty guarantee (the round-30 shared-view lesson).
	if ctx.NormalizedBody == "" || ctx.NormalizedPath == "" {
		t.Fatal("FAIL: raw passthrough left Normalized* fields empty")
	}
}

// Control: the default (NormalizeEncoding=true) keeps today's decoded
// behavior.
func TestNormalizeGateTrueStillDecodes(t *testing.T) {
	cfg := Config{SkipNormalization: false}
	layer := NewLayer(&cfg)
	ctx := gateCtx(t, "/a%2Fb", "%2E%2E%2Fetc%2Fpasswd")
	layer.Process(ctx)
	if ctx.NormalizedBody == "%2E%2E%2Fetc%2Fpasswd" {
		t.Fatal("FAIL: normalize_encoding=true left the body encoded")
	}
}

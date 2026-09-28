package layerregistry

// Regression (round 2026-09-28-sanitizer-deadknobs-wiring): buildSanitizer
// mapped 8 of 11 SanitizerConfig fields — normalize_encoding and
// path_overrides were silently dropped (the layer Config lacked the fields
// entirely), so both knobs were dead in serve mode. buildSanitizer now
// wires them and sanitizer.Config carries NormalizeEncoding plus
// PathOverrides (per-path MaxBodySize, longest prefix wins).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/sanitizer"
)

func sanitizeCtx(t *testing.T, path, body string) *engine.RequestContext {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "http://example.com"+path, nil)
	ctx := engine.AcquireContext(r, 1, 1<<20)
	ctx.Path = path
	ctx.BodyString = body
	ctx.Body = []byte(body)
	return ctx
}

// End-to-end through BuildLayer: a path_overrides entry must tighten
// max_body_size on the matching path.
func TestBuildSanitizer_PathOverrideEnforced(t *testing.T) {
	cfg := &config.Config{}
	cfg.WAF.Sanitizer.Enabled = true
	cfg.WAF.Sanitizer.MaxBodySize = 1000
	cfg.WAF.Sanitizer.NormalizeEncoding = true
	cfg.WAF.Sanitizer.PathOverrides = []config.PathOverride{
		{Path: "/upload", MaxBodySize: 100},
	}

	built, ok, err := BuildLayer("sanitizer", cfg)
	if err != nil || !ok {
		t.Fatalf("BuildLayer(sanitizer): ok=%v err=%v", ok, err)
	}
	layer := built.Layer.(*sanitizer.Layer)

	body := strings.Repeat("A", 200)
	if res := layer.Process(sanitizeCtx(t, "/upload/file", body)); len(res.Findings) == 0 {
		t.Fatal("FAIL: 200-byte body at /upload with override max_body_size 100 produced no finding (override silently ignored)")
	}
	if res := layer.Process(sanitizeCtx(t, "/other", body)); len(res.Findings) != 0 {
		t.Fatalf("FAIL: body under the global limit flagged on /other: %+v", res.Findings)
	}
}

// End-to-end: normalize_encoding=false must pass the raw body through
// NormalizedBody unchanged (raw passthrough, never empty).
func TestBuildSanitizer_NormalizeGateRawPassthrough(t *testing.T) {
	cfg := &config.Config{}
	cfg.WAF.Sanitizer.Enabled = true
	cfg.WAF.Sanitizer.NormalizeEncoding = false

	built, ok, err := BuildLayer("sanitizer", cfg)
	if err != nil || !ok {
		t.Fatalf("BuildLayer(sanitizer): ok=%v err=%v", ok, err)
	}
	layer := built.Layer.(*sanitizer.Layer)

	raw := "%2E%2E%2Fetc%2Fpasswd"
	ctx := sanitizeCtx(t, "/", raw)
	layer.Process(ctx)
	if ctx.NormalizedBody != raw {
		t.Fatalf("FAIL: normalize_encoding=false decoded NormalizedBody to %q", ctx.NormalizedBody)
	}
	if ctx.NormalizedBody == "" {
		t.Fatal("FAIL: raw passthrough left NormalizedBody empty (shared-view blinding)")
	}
}

// Control: the DefaultConfig default (NormalizeEncoding=true) keeps the
// decoded behavior.
func TestBuildSanitizer_DefaultNormalizeDecodes(t *testing.T) {
	cfg := &config.Config{}
	cfg.WAF.Sanitizer.Enabled = true
	cfg.WAF.Sanitizer.NormalizeEncoding = true

	built, ok, err := BuildLayer("sanitizer", cfg)
	if err != nil || !ok {
		t.Fatalf("BuildLayer(sanitizer): ok=%v err=%v", ok, err)
	}
	layer := built.Layer.(*sanitizer.Layer)

	raw := "%2E%2E%2Fetc%2Fpasswd"
	ctx := sanitizeCtx(t, "/", raw)
	layer.Process(ctx)
	if ctx.NormalizedBody == raw {
		t.Fatal("FAIL: normalize_encoding=true left NormalizedBody encoded")
	}
}

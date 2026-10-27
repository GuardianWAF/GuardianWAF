package cors

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression: CORS preflight caching (ADR 0031) must serve the documented
// X-CORS-Cache: hit header for a repeated identical preflight.
//
// ADR 0031 (Status: Implemented) states: "Preflight results are cached per
// origin for `preflight_cache_seconds` duration (default: 600s). Cache hits are
// served with a header `X-CORS-Cache: hit`", and CLAUDE.md's layer table names
// the CORS layer's capabilities as "Origin validation, preflight caching".
// The key is parsed (config.go:888, defaults.go:1143) and mapped into
// cors.Config (layerregistry registry.go:339) — but the layer never reads
// PreflightCacheSeconds and no code anywhere emits X-CORS-Cache.
//
// The test drives the real production path: cors.NewLayer (the same
// constructor layerregistry uses) + engine.AcquireContext + Layer.Process,
// exactly as the pipeline calls it. Assertion: a repeated identical preflight
// must be served as a cache hit (the documented X-CORS-Cache: hit header).
// Controls (must pass before AND after the fix): the first preflight is not a
// hit, a different origin is not a hit, and a different requested method is not
// a hit — a cached hit must never skip strict-mode method/header validation.
func TestPreflightCacheServesDocumentedHitHeader(t *testing.T) {
	cfg := &Config{
		Enabled:               true,
		AllowOrigins:          []string{"https://app.example.com", "https://other.example.com"},
		AllowMethods:          []string{"GET", "POST"},
		AllowHeaders:          []string{"Content-Type"},
		AllowCredentials:      true,
		PreflightCacheSeconds: 600,
	}
	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}

	// preflight runs one real OPTIONS preflight through the layer and returns
	// the preflight response headers the layer emitted.
	preflight := func(origin, method string) map[string]string {
		r := httptest.NewRequest(http.MethodOptions, "/api/orders", nil)
		r.Header.Set("Origin", origin)
		r.Header.Set("Access-Control-Request-Method", method)
		ctx := engine.AcquireContext(r, 1, 1<<20)
		defer engine.ReleaseContext(ctx)

		res := layer.Process(ctx)
		if res.Action != engine.ActionPass {
			t.Fatalf("harness: preflight for allowed origin %q returned action %v", origin, res.Action)
		}
		if len(ctx.CORSPreflightHeaders) == 0 {
			t.Fatalf("harness: no preflight headers were produced for %q", origin)
		}
		return ctx.CORSPreflightHeaders
	}

	// Control 1: a cold cache must not claim a hit.
	if _, hit := preflight("https://app.example.com", "POST")["X-CORS-Cache"]; hit {
		t.Fatalf("CONTROL 1 FAILED: the first preflight already reported a cache hit")
	}
	t.Log("CONTROL 1 PASS: the first preflight is not a cache hit")

	// Control 2: per-origin keying — a different origin must not reuse it.
	if _, hit := preflight("https://other.example.com", "POST")["X-CORS-Cache"]; hit {
		t.Fatalf("CONTROL 2 FAILED: a different origin reported a cache hit")
	}
	t.Log("CONTROL 2 PASS: a different origin is not a cache hit")

	// Control 3: the request signature matters — a different requested method
	// must not reuse the cached verdict (otherwise a cached hit could skip
	// strict-mode method validation).
	if _, hit := preflight("https://app.example.com", "GET")["X-CORS-Cache"]; hit {
		t.Fatalf("CONTROL 3 FAILED: a different requested method reported a cache hit")
	}
	t.Log("CONTROL 3 PASS: a different requested method is not a cache hit")

	// The defect: the identical repeated preflight must be a documented hit.
	hdr := preflight("https://app.example.com", "POST")
	if got := hdr["X-CORS-Cache"]; got != "hit" {
		t.Fatalf("FAIL: ADR 0031 documents CORS preflight caching (CLAUDE.md: \"Origin validation, "+
			"preflight caching\") — \"Preflight results are cached per origin for preflight_cache_seconds "+
			"duration. Cache hits are served with a header X-CORS-Cache: hit\" — but an identical repeated "+
			"preflight produced X-CORS-Cache=%q. PreflightCacheSeconds is parsed and mapped into cors.Config "+
			"(registry.go:339) yet read by nothing in this package, and no code emits X-CORS-Cache", got)
	}
	t.Log("PASS: the repeated preflight was served from cache (X-CORS-Cache: hit)")
}

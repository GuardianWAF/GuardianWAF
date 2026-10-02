package layerregistry

// Regression (hunt round 2026-10-02-response-xcto-knob): buildResponse
// hardcoded `XContentTypeOptions: "nosniff"` into the response layer's
// SecurityHeaders struct and never read cfg.WAF.Response.SecurityHeaders
// .XContentTypeOptions — a real, YAML-mapped, dashboard-exposed knob
// (config.go:697, defaults.go:1733 and the :115 default, read back at
// config_handlers.go:105).
//
// So `x_content_type_options: false` was silently ignored: the operator's
// config said off, the dashboard displayed off, and the header kept being
// emitted on every response. The response layer already models this correctly
// — SecurityHeaders fields are plain strings and Apply() skips empty values
// (headers.go:41-43) — so the builder simply never let the knob be off. This
// is the buildIPACL / buildSanitizer "config knob never reaches the layer"
// family; the two earlier fixes in that vein were both caught by a round that
// re-diffed the builder seam field-by-field.
//
// These tests drive the real serve-mode path: layerregistry.BuildLayer ->
// Layer.Process -> the registered ctx.ResponseHook, i.e. exactly what the
// engine middleware calls to inject headers into each response.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// responseHeadersForConfig builds the real registry-built response layer from
// cfg and returns the headers its hook emits.
func responseHeadersForConfig(t *testing.T, cfg *config.Config) http.Header {
	t.Helper()

	ol, found, err := BuildLayer("response", cfg)
	if err != nil {
		t.Fatalf("BuildLayer(response): %v", err)
	}
	if !found {
		t.Fatal("response layer not found in the registry")
	}

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	ctx := engine.AcquireContext(r, 1, 1<<20)
	defer engine.ReleaseContext(ctx)

	ol.Layer.Process(ctx)
	if ctx.ResponseHook == nil {
		t.Fatal("no ResponseHook registered — the response layer did not run")
	}

	w := httptest.NewRecorder()
	ctx.ResponseHook(w)
	return w.Result().Header
}

// baseResponseHeadersConfig returns a security-headers-enabled config with the
// neighbouring knobs set, so each test varies only the field under test.
func baseResponseHeadersConfig() *config.Config {
	cfg := &config.Config{}
	cfg.WAF.Response.SecurityHeaders.Enabled = true
	cfg.WAF.Response.SecurityHeaders.XFrameOptions = "SAMEORIGIN"
	cfg.WAF.Response.SecurityHeaders.ReferrerPolicy = "strict-origin-when-cross-origin"
	cfg.WAF.Response.SecurityHeaders.PermissionsPolicy = "camera=(), microphone=()"
	return cfg
}

// The defect: an operator who turns the knob off must not get the header.
func TestBuildResponse_XContentTypeOptionsFalseSuppressesHeader(t *testing.T) {
	cfg := baseResponseHeadersConfig()
	cfg.WAF.Response.SecurityHeaders.XContentTypeOptions = false

	if got := responseHeadersForConfig(t, cfg).Get("X-Content-Type-Options"); got != "" {
		t.Fatalf("x_content_type_options: false but the built layer still emitted "+
			"X-Content-Type-Options: %q — buildResponse must not hardcode the header", got)
	}
}

// The default-on path must keep working: config.DefaultConfig sets the knob
// true, so every serve-mode deployment without an explicit override is on.
func TestBuildResponse_XContentTypeOptionsTrueEmitsHeader(t *testing.T) {
	cfg := baseResponseHeadersConfig()
	cfg.WAF.Response.SecurityHeaders.XContentTypeOptions = true

	if got := responseHeadersForConfig(t, cfg).Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("x_content_type_options: true must emit nosniff, got %q", got)
	}
}

// Boundary: the shipped default (config.DefaultConfig) must emit the header,
// so the fix cannot regress the out-of-the-box posture.
func TestBuildResponse_DefaultConfigEmitsHeader(t *testing.T) {
	cfg := config.DefaultConfig()

	if !cfg.WAF.Response.SecurityHeaders.XContentTypeOptions {
		t.Fatal("precondition: DefaultConfig should enable x_content_type_options")
	}
	if got := responseHeadersForConfig(t, cfg).Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("default config must emit nosniff, got %q", got)
	}
}

// Control: the neighbouring mapped knobs share the same struct literal and
// must keep flowing through regardless of the x_content_type_options setting.
func TestBuildResponse_NeighbouringHeadersUnaffected(t *testing.T) {
	for _, xcto := range []bool{true, false} {
		cfg := baseResponseHeadersConfig()
		cfg.WAF.Response.SecurityHeaders.XContentTypeOptions = xcto
		h := responseHeadersForConfig(t, cfg)

		if got := h.Get("X-Frame-Options"); got != "SAMEORIGIN" {
			t.Fatalf("xcto=%v: X-Frame-Options = %q, want SAMEORIGIN", xcto, got)
		}
		if got := h.Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
			t.Fatalf("xcto=%v: Referrer-Policy = %q, want strict-origin-when-cross-origin", xcto, got)
		}
		if got := h.Get("Permissions-Policy"); got != "camera=(), microphone=()" {
			t.Fatalf("xcto=%v: Permissions-Policy = %q, want camera=(), microphone=()", xcto, got)
		}
	}
}

// Control: with security headers disabled entirely, the layer registers no
// header hook at all (response.go gates on SecurityHeadersEnabled), so the
// knob must not create a path around that master switch.
func TestBuildResponse_MasterSwitchStillGatesAllHeaders(t *testing.T) {
	cfg := baseResponseHeadersConfig()
	cfg.WAF.Response.SecurityHeaders.Enabled = false
	cfg.WAF.Response.SecurityHeaders.XContentTypeOptions = true

	ol, found, err := BuildLayer("response", cfg)
	if err != nil {
		t.Fatalf("BuildLayer(response): %v", err)
	}
	if !found {
		t.Fatal("response layer not found in the registry")
	}

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	ctx := engine.AcquireContext(r, 1, 1<<20)
	defer engine.ReleaseContext(ctx)

	ol.Layer.Process(ctx)

	if ctx.ResponseHook != nil {
		w := httptest.NewRecorder()
		ctx.ResponseHook(w)
		for _, name := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"} {
			if got := w.Result().Header.Get(name); got != "" {
				t.Fatalf("security_headers.enabled: false but %s was emitted: %q", name, got)
			}
		}
		t.Fatal("security_headers.enabled: false but the layer registered a ResponseHook")
	}
}

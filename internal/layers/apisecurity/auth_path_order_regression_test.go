package apisecurity

// Regression: the canonical-path view in Process must work in the REAL
// pipeline, not only in hand-built contexts.
//
// ctx.NormalizedPath is written only by the sanitizer (sanitizer.go:63/103),
// which runs at engine.OrderSanitizer = 300, while this layer runs at
// engine.OrderAPISecurity = 275. A previous fix read the field and fell back
// to the raw ctx.Path when it was empty — on every live request it WAS empty,
// so the fallback silently re-opened the dot-segment bypass: the skip_paths
// auth EXEMPTION applied to "/health/../admin" and a key scoped "/api/*"
// authorized "/api/../admin/secrets".
//
// The earlier regression (auth_path_canon_test.go) hand-builds a
// RequestContext with NormalizedPath already set — a state the pipeline never
// produces — so it stayed green while the live path was open. These tests
// therefore drive the real engine pipeline over layers sorted by their real
// Order() constants, which is the only way to observe the defect.

import (
	"bufio"
	"net/http"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/sanitizer"
)

// newOrderProbeEngine wires api_security + sanitizer into a real engine so the
// pipeline executes them in production order.
func newOrderProbeEngine(t *testing.T) *engine.Engine {
	t.Helper()

	eng, err := engine.NewEngine(config.DefaultConfig(),
		events.NewMemoryStore(256), events.NewEventBus())
	if err != nil {
		t.Fatalf("harness setup failed: NewEngine: %v", err)
	}

	apiLayer, err := NewLayer(&Config{
		Enabled:    true,
		SkipPaths:  []string{"/health*"},
		HeaderName: "X-API-Key",
		APIKeys: APIKeysConfig{
			Enabled:    true,
			HeaderName: "X-API-Key",
			Keys: []APIKeyConfig{{
				Name:         "svc",
				KeyHash:      "s3cret-api-key",
				AllowedPaths: []string{"/api/*"},
				Enabled:      true,
			}},
		},
	})
	if err != nil {
		t.Fatalf("harness setup failed: apisecurity.NewLayer: %v", err)
	}

	sanLayer := sanitizer.NewLayer(&sanitizer.Config{
		MaxURLLength:   8192,
		MaxHeaderSize:  64 * 1024,
		MaxHeaderCount: 150,
		MaxBodySize:    1 << 20,
		MaxCookieSize:  4096,
		BlockNullBytes: true,
	})

	eng.AddLayer(engine.OrderedLayer{Layer: apiLayer, Order: apiLayer.Order()})
	eng.AddLayer(engine.OrderedLayer{Layer: sanLayer, Order: sanLayer.Order()})

	return eng
}

func pipelineAction(t *testing.T, eng *engine.Engine, rawRequest string) engine.Action {
	t.Helper()

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rawRequest)))
	if err != nil {
		t.Fatalf("harness setup failed: could not parse request: %v", err)
	}
	req.RemoteAddr = "203.0.113.10:5555"

	ev := eng.Check(req)
	if ev == nil {
		t.Fatalf("harness setup failed: Check returned nil event")
	}
	return ev.Action
}

const orderProbeNoAuth = "HTTP/1.1\r\nHost: app.example.com\r\n\r\n"
const orderProbeWithKey = "HTTP/1.1\r\nHost: app.example.com\r\nX-API-Key: s3cret-api-key\r\n\r\n"

// THE DEFECT: with the sanitizer running AFTER this layer in the real
// pipeline, a dot-segment spelling must not inherit the skip_paths exemption
// nor escape an allowed_paths scope. Pre-fix both passed with action=pass.
func TestAuthPathCanonical_RealPipelineNotBypassed(t *testing.T) {
	t.Run("dot_segment_does_not_inherit_skip_exemption", func(t *testing.T) {
		eng := newOrderProbeEngine(t)
		if action := pipelineAction(t, eng, "GET /health/../admin "+orderProbeNoAuth); action != engine.ActionBlock {
			t.Errorf("skip_paths exemption granted to /health/../admin (action=%v); upstream serves /admin", action)
		}
	})

	t.Run("traversal_does_not_escape_allowed_paths", func(t *testing.T) {
		eng := newOrderProbeEngine(t)
		if action := pipelineAction(t, eng, "GET /api/../admin/secrets "+orderProbeWithKey); action != engine.ActionBlock {
			t.Errorf("key scoped /api/* authorized /api/../admin/secrets (action=%v)", action)
		}
	})

	t.Run("double_slash_does_not_inherit_skip_exemption", func(t *testing.T) {
		eng := newOrderProbeEngine(t)
		if action := pipelineAction(t, eng, "GET /health//../admin "+orderProbeNoAuth); action != engine.ActionBlock {
			t.Errorf("skip_paths exemption granted to /health//../admin (action=%v)", action)
		}
	})
}

// Controls: the legitimate behaviours must be preserved through the same
// pipeline. A fix that simply broke exemptions/scopes would pass the tests
// above and is not acceptable.
func TestAuthPathCanonical_RealPipelineControls(t *testing.T) {
	t.Run("legitimate_skip_path_still_exempt", func(t *testing.T) {
		eng := newOrderProbeEngine(t)
		if action := pipelineAction(t, eng, "GET /health/live "+orderProbeNoAuth); action != engine.ActionPass {
			t.Errorf("/health/live should stay exempt (action=%v)", action)
		}
	})

	t.Run("protected_path_without_credentials_blocked", func(t *testing.T) {
		eng := newOrderProbeEngine(t)
		if action := pipelineAction(t, eng, "GET /admin "+orderProbeNoAuth); action != engine.ActionBlock {
			t.Errorf("/admin without credentials should be blocked (action=%v)", action)
		}
	})

	t.Run("valid_key_inside_scope_still_passes", func(t *testing.T) {
		eng := newOrderProbeEngine(t)
		if action := pipelineAction(t, eng, "GET /api/users "+orderProbeWithKey); action != engine.ActionPass {
			t.Errorf("valid key on /api/users should pass (action=%v)", action)
		}
	})
}

// The unit-level contract the hand-built tests missed: with NormalizedPath
// EMPTY — the state every live request is in, because this layer runs before
// the sanitizer — the layer must canonicalize ctx.Path itself instead of
// falling back to the raw wire path. Driving Process directly here is the
// only way to assert that state, since the old tests always pre-populated it.
func TestAuthPathCanonical_UsesWirePathWhenNormalizedAbsent(t *testing.T) {
	layer, err := NewLayer(&Config{
		Enabled:   true,
		SkipPaths: []string{"/health*"},
		APIKeys: APIKeysConfig{
			Enabled:    true,
			HeaderName: "X-API-Key",
			Keys: []APIKeyConfig{{
				Name: "svc", KeyHash: "s3cret-api-key",
				AllowedPaths: []string{"/api/*"}, Enabled: true,
			}},
		},
	})
	if err != nil {
		t.Fatalf("harness setup failed: NewLayer: %v", err)
	}

	newCtx := func(path, normalized string) *engine.RequestContext {
		return &engine.RequestContext{
			Path:           path,
			NormalizedPath: normalized,
			Headers:        map[string][]string{},
			QueryParams:    map[string][]string{},
			Metadata:       map[string]any{},
			Method:         http.MethodGet,
		}
	}

	t.Run("empty_normalized_does_not_grant_exemption", func(t *testing.T) {
		ctx := newCtx("/health/../admin", "") // production state at order 275
		if res := layer.Process(ctx); res.Action == engine.ActionPass {
			t.Errorf("skip exemption granted on raw wire path %q with NormalizedPath empty", ctx.Path)
		}
	})

	t.Run("empty_normalized_does_not_escape_allowed_paths", func(t *testing.T) {
		ctx := newCtx("/api/../admin/secrets", "")
		ctx.Headers = map[string][]string{"X-Api-Key": {"s3cret-api-key"}}
		if res := layer.Process(ctx); res.Action == engine.ActionPass {
			t.Errorf("key scoped /api/* authorized %q with NormalizedPath empty", ctx.Path)
		}
	})

	t.Run("populated_normalized_still_honoured", func(t *testing.T) {
		// The scenario the pre-existing auth_path_canon_test.go covers; it must
		// keep working, and must not be the ONLY covered state.
		ctx := newCtx("/health/../admin", "/admin")
		if res := layer.Process(ctx); res.Action == engine.ActionPass {
			t.Errorf("skip exemption applied for canonical path %q", ctx.NormalizedPath)
		}
	})

	t.Run("legitimate_exemption_still_granted", func(t *testing.T) {
		ctx := newCtx("/health/live", "")
		if res := layer.Process(ctx); res.Action != engine.ActionPass {
			t.Errorf("/health/live should stay exempt (action=%v)", res.Action)
		}
	})
}

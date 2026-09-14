package apisecurity

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (hunt round 8/25): both path-based authentication decisions in
// this layer — the skip_paths auth exemption and the API-key allowed_paths
// scope check — were evaluated against the RAW wire path (ctx.Path), whose
// dot-segments upstreams resolve. A request for /health/../admin matched the
// /health* skip prefix (auth exemption on a non-exempt path) and a request
// for /api/../admin/secrets matched the /api/* allowlist (scope escape),
// while the canonical path — what the sanitizer resolves and upstreams
// serve — was /admin and /admin/secrets respectively. Path security must
// evaluate the canonical form (NormalizedPath, falling back to raw when the
// sanitizer layer is disabled — the ratelimit layer's dual view).

func newAuthLayer(t *testing.T) *Layer {
	t.Helper()
	l, err := NewLayer(&Config{
		Enabled:   true,
		SkipPaths: []string{"/health*"},
		APIKeys: APIKeysConfig{
			Enabled: true,
			Keys: []APIKeyConfig{{
				Name:         "scoped",
				KeyHash:      "scoped-key",
				AllowedPaths: []string{"/api/*"},
				Enabled:      true,
			}},
		},
	})
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}
	return l
}

func TestSkipPathDoesNotApplyToDotSegmentForms(t *testing.T) {
	l := newAuthLayer(t)

	// The raw path prefix-matches /health*, but its canonical resolution is
	// /admin — a non-exempt path. No credentials are presented, so the only
	// thing that lets this request pass is the bogus exemption.
	ctx := &engine.RequestContext{
		Method:         "GET",
		Path:           "/health/../admin",
		NormalizedPath: "/admin",
		Headers:        map[string][]string{},
		Cookies:        map[string][]string{},
		Metadata:       map[string]any{},
	}
	if res := l.Process(ctx); res.Action == engine.ActionPass {
		t.Fatalf("FAIL: dot-segment form of a non-exempt path received the /health* auth exemption (raw-prefix match on the wire path)")
	}
}

// Control: the genuine exempt path keeps its exemption.
func TestSkipPathStillExemptCanonicalForm(t *testing.T) {
	l := newAuthLayer(t)

	ctx := &engine.RequestContext{
		Method:         "GET",
		Path:           "/health/live",
		NormalizedPath: "/health/live",
		Headers:        map[string][]string{},
		Cookies:        map[string][]string{},
		Metadata:       map[string]any{},
	}
	if res := l.Process(ctx); res.Action != engine.ActionPass {
		t.Fatalf("FAIL: canonical /health/live lost its auth exemption: %v", res.Findings)
	}
}

func TestAllowedPathsScopeNotEscapedByDotSegments(t *testing.T) {
	l := newAuthLayer(t)

	// The raw path prefix-matches /api/*, but its canonical resolution is
	// /admin/secrets — outside the key's allowed scope.
	ctx := &engine.RequestContext{
		Method:         "GET",
		Path:           "/api/../admin/secrets",
		NormalizedPath: "/admin/secrets",
		Headers:        map[string][]string{"X-API-Key": {"scoped-key"}},
		Cookies:        map[string][]string{},
		Metadata:       map[string]any{},
	}
	if res := l.Process(ctx); res.Action == engine.ActionPass {
		t.Fatalf("FAIL: /api/../admin/secrets passed the /api/* allowlist via the raw wire path (scope escape)")
	}

	// Control: the conforming form stays allowed.
	ok := &engine.RequestContext{
		Method:         "GET",
		Path:           "/api/users",
		NormalizedPath: "/api/users",
		Headers:        map[string][]string{"X-API-Key": {"scoped-key"}},
		Cookies:        map[string][]string{},
		Metadata:       map[string]any{},
	}
	if r := l.Process(ok); r.Action != engine.ActionPass {
		t.Fatalf("FAIL: conforming in-scope request blocked: %v", r.Findings)
	}
}

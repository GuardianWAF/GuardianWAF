package ratelimit

import (
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression tests for "/**" subtree pattern semantics in rate-limit rules:
// "/api/**" means "everything under the /api path segment tree" — it must
// NOT match sibling paths that merely share the string prefix ("​/apifoo",
// "/api/v10/..."). The pre-fix implementation used a raw strings.HasPrefix
// against the pattern prefix, so "/apifoo" was rate-limited by a rule the
// operator scoped to "/api/**".

func TestRateLimitSubtreePatternDoesNotMatchPrefixSiblings(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{
				ID:     "api",
				Scope:  "ip+path",
				Paths:  []string{"/api/**"},
				Limit:  2,
				Window: 1 * time.Hour,
				Burst:  2,
				Action: "block",
			},
		},
	})

	// Sibling path sharing only the string prefix: the /api/** rule must
	// never apply, so 10 requests must all pass.
	for i := 0; i < 10; i++ {
		ctx := makeContext("1.2.3.4", "/apifoo")
		result := layer.Process(ctx)
		engine.ReleaseContext(ctx)
		if result.Action == engine.ActionBlock {
			t.Fatalf("FAIL: rule scoped to /api/** blocked request %d to sibling path /apifoo (segment-boundary overmatch)", i+1)
		}
	}

	// Positive control: the subtree itself must still be enforced — the 3rd
	// request to /api/users exceeds Limit 2 and is blocked. (ip+path scope
	// keys buckets per path, so this bucket is independent of /apifoo.)
	for i := 0; i < 2; i++ {
		ctx := makeContext("1.2.3.4", "/api/users")
		layer.Process(ctx)
		engine.ReleaseContext(ctx)
	}
	ctx := makeContext("1.2.3.4", "/api/users")
	result := layer.Process(ctx)
	engine.ReleaseContext(ctx)
	if result.Action != engine.ActionBlock {
		t.Fatal("FAIL: /api/** stopped enforcing its own subtree")
	}
}

// TestMatchPathMultiLevelPrefixSegmentBoundary pins the boundary at the
// pattern's own depth: /api/v1/** must not swallow /api/v10/... .
func TestMatchPathMultiLevelPrefixSegmentBoundary(t *testing.T) {
	if matchPath("/api/v1/**", "/api/v10/detail") {
		t.Fatal("FAIL: /api/v1/** matched /api/v10/detail (multi-level segment-boundary overmatch)")
	}
	if !matchPath("/api/v1/**", "/api/v1/users") {
		t.Fatal("/api/v1/** must still match its own subtree")
	}
	if !matchPath("/api/v1/**", "/api/v1") {
		t.Fatal("/api/v1/** must still match the prefix path itself")
	}
	if !matchPath("/api/**", "/api/") {
		t.Fatal("/api/** must still match /api/")
	}
}

package cors

// Regression (bug-hunt round 2026-09-18-r6, closing the round-80 record's
// deliberately-deferred note): isAllOriginsWildcard rejected only hosts made
// entirely of '*', so the adjacent all-stars-and-dots spellings — "https://*.",
// "https://*.*", "*://*." — passed the AllowCredentials guard in both
// NewLayer and UpdateConfig, while compileWildcard turned each into a broad
// match-broad regex: "https://*." compiles to ^https://.+\.+$, which matches
// every trailing-dot origin ("https://evil.com." — resolves identically to
// evil.com, shares its cookie jar, and browsers preserve the trailing dot in
// Origin serialization). With AllowCredentials the layer then reflected
// Access-Control-Allow-Origin: https://evil.com. plus
// Access-Control-Allow-Credentials: true — credentialed CORS for arbitrary
// sites, the exact posture the guard's own error message promises to reject
// at construction (CWE-942 family).
//
// The fix generalizes the structural check: a wildcard-pattern host composed
// only of '*' and '.' separators (no literal host-label characters) can never
// express a scoped allowlist — every such shape compiles to a match-broad
// regex — so the guard rejects the whole family. Scoped patterns
// ("https://*.example.com") and TLD-wide patterns ("https://*.com") carry
// literal label characters and stay allowed with credentials.

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestExoticAllHostsWildcardSpellingsWithCredentialsRejected(t *testing.T) {
	spellings := []string{
		"https://*.",
		"https://*.*",
		"http://*.",
		"*://*.",
		"https://*..",
	}
	for _, spelling := range spellings {
		cfg := &Config{
			Enabled:          true,
			AllowOrigins:     []string{spelling},
			AllowMethods:     []string{"GET", "POST"},
			AllowCredentials: true,
		}
		if _, err := NewLayer(cfg); err == nil {
			t.Fatalf("FAIL: all-stars-and-dots wildcard %q with AllowCredentials accepted — it compiles to a match-broad regex (e.g. every trailing-dot origin), reflecting credentialed CORS for arbitrary sites", spelling)
		}
	}
}

// TestUpdateConfigRejectsExoticAllHostsWildcardSpellings pins the same
// structural rejection at runtime, and that a rejected update must not
// half-apply — the previously active allowlist stays in force.
func TestUpdateConfigRejectsExoticAllHostsWildcardSpellings(t *testing.T) {
	l, err := NewLayer(&Config{
		Enabled:          true,
		AllowOrigins:     []string{"https://app.example.com"},
		AllowMethods:     []string{"GET"},
		AllowCredentials: true,
	})
	if err != nil {
		t.Fatalf("FAIL: baseline layer rejected: %v", err)
	}

	spellings := []string{"https://*.", "https://*.*", "*://*."}
	for _, spelling := range spellings {
		err := l.UpdateConfig(Config{
			Enabled:          true,
			AllowOrigins:     []string{spelling},
			AllowMethods:     []string{"GET", "POST"},
			AllowCredentials: true,
		})
		if err == nil {
			t.Fatalf("FAIL: UpdateConfig accepted all-stars-and-dots wildcard %q with AllowCredentials", spelling)
		}
	}

	// The failed updates must not have mutated layer state.
	ctx := &engine.RequestContext{
		Method:  "GET",
		Headers: map[string][]string{"Origin": {"https://app.example.com"}},
	}
	l.Process(ctx)
	if ctx.CORSHeaders["Access-Control-Allow-Origin"] != "https://app.example.com" {
		t.Fatalf("FAIL: rejected UpdateConfig half-applied — previously allowed origin no longer served: %v", ctx.CORSHeaders)
	}

	ctx = &engine.RequestContext{
		Method:  "GET",
		Headers: map[string][]string{"Origin": {"http://evil.example.net"}},
	}
	l.Process(ctx)
	if len(ctx.CORSHeaders) != 0 {
		t.Fatalf("FAIL: rejected UpdateConfig half-applied — foreign origin got CORS headers: %v", ctx.CORSHeaders)
	}
}

// Controls: patterns carrying literal host-label characters stay allowed
// with credentials — the guard must generalize to the all-hosts family
// WITHOUT over-rejecting scoped or TLD-wide wildcards.
func TestScopedAndTLDPatternsStillAllowedWithCredentials(t *testing.T) {
	for _, spelling := range []string{"https://*.example.com", "https://*.com"} {
		cfg := &Config{
			Enabled:          true,
			AllowOrigins:     []string{spelling},
			AllowCredentials: true,
		}
		if _, err := NewLayer(cfg); err != nil {
			t.Fatalf("FAIL: harness control — scoped pattern %q with credentials must stay allowed, got: %v", spelling, err)
		}
	}
}

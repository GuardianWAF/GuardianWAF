package cors

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression: the all-origins wildcard ("https://*") combined with
// AllowCredentials silently granted credentialed CORS to every https origin.
// Because ACAO is the REFLECTED origin (never the literal "*"), the browser
// honors the combination — this is the credentials-leak amplifier the
// wildcard+credentials rejection in the CORS spec exists to prevent.
func TestWildcardAllWithCredentialsRejected(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		AllowOrigins:     []string{"https://*"},
		AllowCredentials: true,
		AllowMethods:     []string{"GET", "POST"},
	}
	if _, err := NewLayer(cfg); err == nil {
		t.Fatalf("FAIL: all-origins wildcard with AllowCredentials accepted — reflected ACAO plus credentials grants every https origin credentialed access")
	}
}

// Control: a scoped wildcard with credentials is the legitimate credentialed
// pattern and must keep working; non-allowlisted origins get no CORS headers.
func TestScopedWildcardWithCredentialsStillAllowed(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		AllowOrigins:     []string{"https://*.example.com"},
		AllowCredentials: true,
	}
	l, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("FAIL: scoped wildcard with credentials rejected: %v", err)
	}
	ctx := &engine.RequestContext{
		Method:  "GET",
		Headers: map[string][]string{"Origin": {"https://evil.example.net"}},
	}
	l.Process(ctx)
	if len(ctx.CORSHeaders) != 0 {
		t.Fatalf("FAIL: non-allowlisted origin got CORS headers: %v", ctx.CORSHeaders)
	}
}

// Control: the all-origins wildcard WITHOUT credentials is the public-API
// style and stays allowed; the origin is reflected without credentials.
func TestWildcardAllWithoutCredentialsAllowed(t *testing.T) {
	cfg := &Config{
		Enabled:      true,
		AllowOrigins: []string{"https://*"},
	}
	l, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("FAIL: wildcard without credentials rejected: %v", err)
	}
	ctx := &engine.RequestContext{
		Method:  "GET",
		Headers: map[string][]string{"Origin": {"https://any.example.net"}},
	}
	l.Process(ctx)
	if ctx.CORSHeaders["Access-Control-Allow-Origin"] != "https://any.example.net" {
		t.Fatalf("FAIL: wildcard origin not reflected: %v", ctx.CORSHeaders)
	}
	if ctx.CORSHeaders["Access-Control-Allow-Credentials"] == "true" {
		t.Fatalf("FAIL: credentials enabled without config")
	}
}

// Regression: the round-43 guard compared the normalized origin against the
// single spelling "https://*", so all-origins wildcards that normalize
// differently — "http://*", "*://*", "https://**" — slipped through in both
// NewLayer and UpdateConfig. compileWildcard turns each into a bare
// `^<scheme>://.+$` regex, so with AllowCredentials the layer reflected
// Access-Control-Allow-Origin plus Access-Control-Allow-Credentials: true for
// every host of that scheme. The rejection must be structural, not spelling-
// specific.
func TestAllOriginsWildcardSpellingsWithCredentialsRejected(t *testing.T) {
	spellings := []string{"https://*", "http://*", "*://*", "https://**"}
	for _, spelling := range spellings {
		cfg := &Config{
			Enabled:          true,
			AllowOrigins:     []string{spelling},
			AllowMethods:     []string{"GET", "POST"},
			AllowCredentials: true,
		}
		if _, err := NewLayer(cfg); err == nil {
			t.Fatalf("FAIL: all-origins wildcard %q with AllowCredentials accepted — reflected ACAO plus credentials grants every host of the scheme credentialed access", spelling)
		}
	}
}

// Regression: UpdateConfig must enforce the same structural rejection at
// runtime, and a rejected config must not half-apply — the previously active
// allowlist stays in force.
func TestUpdateConfigRejectsAllOriginsWildcardSpellings(t *testing.T) {
	l, err := NewLayer(&Config{
		Enabled:          true,
		AllowOrigins:     []string{"https://app.example.com"},
		AllowMethods:     []string{"GET"},
		AllowCredentials: true,
	})
	if err != nil {
		t.Fatalf("FAIL: baseline layer rejected: %v", err)
	}

	spellings := []string{"https://*", "http://*", "*://*", "https://**"}
	for _, spelling := range spellings {
		err := l.UpdateConfig(Config{
			Enabled:          true,
			AllowOrigins:     []string{spelling},
			AllowMethods:     []string{"GET", "POST"},
			AllowCredentials: true,
		})
		if err == nil {
			t.Fatalf("FAIL: UpdateConfig accepted all-origins wildcard %q with AllowCredentials", spelling)
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

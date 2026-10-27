package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/runtime/layerregistry"
)

// Regression: a schema declared in `waf.api_validation.schemas` must be able to carry a
// `name` so the upload route can replace or remove it by identity; without one it is
// append-only (its file path remains the only handle, and only for removal).
//
// Originally: a schema declared in `waf.api_validation.schemas` could not be
// given an identity, so an upload can never REPLACE it.
//
// Layer.LoadSchema replaces by Source.Name and requires a non-empty incoming
// name, while config-declared sources are built with an empty Source.Name
// (config.SchemaSourceConfig has no name field). Removal is asymmetric: it also
// works by Source.Path (RemoveSchema matches Path == name), so a config-declared
// schema can be deleted by typing its file path — but never replaced.
//
// Assertion 1: a config schema source must be able to carry a `name`
// so it has a stable identity. Pre-fix the key is rejected outright as an
// unknown key, i.e. the identity is not even expressible.
// Assertion 2: with that name, an upload under the same name REPLACES the
// config-declared spec (its path, declared only there, stops being enforced).
// The identity is proven behaviourally, so the test never touches the Go field
// directly: it fails on the contract, not on a missing struct member.
// Assertion 3: RemoveAPISchema(name) then removes it by name.
// Control C1: an unnamed config source keeps append semantics (an upload never
// replaces it) — must hold before AND after the fix.
const declaredSpecYAML = `openapi: 3.0.0
info:
  title: declared
  version: "1.0.0"
paths:
  /api/declared:
    get:
      parameters:
        - name: d
          in: query
          required: true
          schema:
            type: string
      responses:
        "200":
          description: ok
  /api/declared-only:
    get:
      parameters:
        - name: k
          in: query
          required: true
          schema:
            type: string
      responses:
        "200":
          description: ok
`

// replacementSpecYAML declares only /api/declared (with a different required
// parameter), so /api/declared-only proves whether the replaced spec is gone.
const replacementSpecYAML = `openapi: 3.0.0
info:
  title: orders
  version: "2.0.0"
paths:
  /api/declared:
    get:
      parameters:
        - name: d2
          in: query
          required: true
          schema:
            type: string
      responses:
        "200":
          description: ok
`

const (
	declaredSpecPath = "zz_r12_declared_spec.yaml"
	namedCfgPath     = "zz_r12_named_config.yaml"
	unnamedCfgPath   = "zz_r12_unnamed_config.yaml"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
}

// serveWith builds the layer through the registry (real serve wiring) and
// returns a GET helper plus the MCP adapter for that engine.
func serveWith(t *testing.T, cfg *config.Config) (func(string) int, *mcpEngineAdapter) {
	t.Helper()
	layer, ok, err := layerregistry.BuildLayer("api_validation", cfg)
	if err != nil || !ok {
		t.Fatalf("harness: api_validation layer not built (ok=%v err=%v)", ok, err)
	}
	store := events.NewMemoryStore(64)
	eng, err := engine.NewEngine(cfg, store, events.NewEventBus())
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close() })
	eng.AddLayer(layer)

	srv := httptest.NewServer(eng.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	})))
	t.Cleanup(srv.Close)

	get := func(path string) int {
		resp, gerr := http.Get(srv.URL + path)
		if gerr != nil {
			t.Fatalf("GET %s: %v", path, gerr)
		}
		defer resp.Body.Close()
		_, _ = io.ReadAll(resp.Body)
		return resp.StatusCode
	}
	return get, &mcpEngineAdapter{engine: eng, cfg: cfg, eventStore: store}
}

func TestDeclaredSchemaIdentityEnablesUploadReplacement(t *testing.T) {
	writeFile(t, declaredSpecPath, declaredSpecYAML)

	apiBlock := func(name string) string {
		nameLine := ""
		if name != "" {
			nameLine = "\n        name: " + name
		}
		return fmt.Sprintf(`waf:
  api_validation:
    enabled: true
    validate_request: true
    strict_mode: false
    block_on_violation: true
    violation_score: 40
    cache_size: 100
    schemas:
      - path: %s
        type: openapi%s
`, declaredSpecPath, nameLine)
	}
	writeFile(t, namedCfgPath, apiBlock("orders"))
	writeFile(t, unnamedCfgPath, apiBlock(""))

	// --- Assertion 1: the identity must be expressible in config. ---
	namedCfg, err := config.LoadFile(namedCfgPath)
	if err != nil {
		t.Fatalf("FAIL: a schema declared in waf.api_validation.schemas cannot be given an identity — "+
			"the `name` key is rejected (%v). Layer.LoadSchema replaces by Source.Name and requires a "+
			"non-empty incoming name, while config-declared sources are built with an empty Source.Name, "+
			"so no upload can ever REPLACE this schema: an operator can only delete it by typing its file "+
			"path (RemoveSchema also matches Source.Path)", err)
	}
	get, adapter := serveWith(t, namedCfg)

	// Harness sanity: the declared schema is enforced.
	if get("/api/declared") == http.StatusOK {
		t.Fatalf("harness: the declared schema is not enforced")
	}

	// --- Assertion 2: an upload under the same name replaces the declared spec. ---
	if err := adapter.UploadAPISchema("orders", replacementSpecYAML, "openapi", false); err != nil {
		t.Fatalf("UploadAPISchema: %v", err)
	}
	if get("/api/declared-only") != http.StatusOK {
		t.Fatalf("FAIL: an upload named after the config-declared schema did not replace it — " +
			"/api/declared-only, declared only by the replaced spec, is still enforced")
	}
	if get("/api/declared") == http.StatusOK {
		t.Fatalf("FAIL: the replacement upload's own contract is not enforced")
	}

	// --- Assertion 3: the schema is removable by its identity. ---
	if err := adapter.RemoveAPISchema("orders"); err != nil {
		t.Fatalf("RemoveAPISchema(orders): %v", err)
	}
	if get("/api/declared") != http.StatusOK {
		t.Fatalf("FAIL: removing the schema by its identity left enforcement behind")
	}

	// --- Control C1: an unnamed config source keeps append semantics. ---
	unnamedCfg, err := config.LoadFile(unnamedCfgPath)
	if err != nil {
		t.Fatalf("CONTROL C1 FAILED (harness): unnamed config did not load: %v", err)
	}
	getU, adapterU := serveWith(t, unnamedCfg)
	if getU("/api/declared-only") == http.StatusOK {
		t.Fatalf("CONTROL C1 FAILED: the unnamed config-declared schema was not enforced")
	}
	if err := adapterU.UploadAPISchema("orders", replacementSpecYAML, "openapi", false); err != nil {
		t.Fatalf("CONTROL C1: upload: %v", err)
	}
	// Append semantics: the unnamed config spec survives, so the path only it
	// declares must STILL be enforced after the upload.
	if getU("/api/declared-only") == http.StatusOK {
		t.Fatalf("CONTROL C1 FAILED: an upload replaced an UNNAMED config-declared schema — config " +
			"sources must keep append semantics unless they opt into an identity")
	}
	t.Log("CONTROL C1 PASS: an unnamed config-declared schema is not replaceable by an upload")
}

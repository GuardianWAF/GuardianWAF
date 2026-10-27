package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/apivalidation"
	"github.com/guardianwaf/guardianwaf/internal/runtime/layerregistry"
)

// Regression: the runtime schema-upload path (MCP UploadAPISchema -> dashboard
// adapter -> apivalidation.Layer.LoadSchema) must keep enforcing on a layer
// built through layerregistry.BuildLayer — i.e. one that already holds the
// schemas declared in `waf.api_validation.schemas` since round 10.
//
// Assertions:
//  1. the startup-declared schema is enforced (the round-10 behaviour);
//  2. an uploaded schema is enforced alongside it;
//  3. a re-upload under the same operator-assigned name REPLACES the previous
//     upload. The distinguishing observable is a path the new upload REMOVES:
//     the router is keyed by method+path, so a path present in both versions
//     behaves identically whether the old spec was dropped or merely appended
//     (the later compile overwrites the route). Only a removed path proves the
//     replaced spec is gone — with append semantics its stale route stays
//     enforced, which is the failure the replace logic exists to prevent;
//  4. the startup-declared spec keeps being enforced after the uploads (config
//     sources carry no Source.Name, so by design only an upload replaces an
//     upload).
const startupSpecYAML = `openapi: 3.0.0
info:
  title: startup
  version: "1.0.0"
paths:
  /api/startup:
    get:
      parameters:
        - name: s
          in: query
          required: true
          schema:
            type: string
      responses:
        "200":
          description: ok
`

// uploadedSpecV1 declares two paths; uploadedSpecV2 (same upload name) declares
// only /api/orders and renames the required parameter.
func uploadedSpecV1() string {
	return `openapi: 3.0.0
info:
  title: orders
  version: "1.0.0"
paths:
  /api/orders:
    get:
      parameters:
        - name: v1
          in: query
          required: true
          schema:
            type: string
      responses:
        "200":
          description: ok
  /api/legacy:
    get:
      parameters:
        - name: L
          in: query
          required: true
          schema:
            type: string
      responses:
        "200":
          description: ok
`
}

func uploadedSpecV2() string {
	return `openapi: 3.0.0
info:
  title: orders
  version: "2.0.0"
paths:
  /api/orders:
    get:
      parameters:
        - name: v2
          in: query
          required: true
          schema:
            type: string
      responses:
        "200":
          description: ok
`
}

func TestUploadedSchemaEnforcedOnRegistryBuiltLayer(t *testing.T) {
	// The declared schema must sit under CWD: Layer.readFile confines schema
	// files to the process working directory.
	const startupPath = "zz_upload_regression_startup_spec.yaml"
	if err := os.WriteFile(startupPath, []byte(startupSpecYAML), 0o600); err != nil {
		t.Fatalf("write startup spec: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(startupPath) })

	cfg := config.DefaultConfig()
	cfg.WAF.APIValidation = config.APIValidationConfig{
		Enabled:          true,
		ValidateRequest:  true,
		ValidateResponse: false,
		StrictMode:       false,
		BlockOnViolation: true,
		ViolationScore:   40,
		CacheSize:        100,
		Schemas:          []config.SchemaSourceConfig{{Path: startupPath, Type: "openapi"}},
	}

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
	blocked := func(path string) bool { return get(path) != http.StatusOK }

	// 1. The startup-declared schema (round 10) is enforced.
	if !blocked("/api/startup") {
		t.Fatalf("ASSERTION 1 FAILED: the schema declared in waf.api_validation.schemas was not enforced " +
			"(a request missing the required parameter `s` was not blocked)")
	}

	// Drive the real MCP upload route against this registry-built layer.
	adapter := &mcpEngineAdapter{engine: eng, cfg: cfg, eventStore: store}
	if err := adapter.UploadAPISchema("orders", uploadedSpecV1(), "openapi", false); err != nil {
		t.Fatalf("UploadAPISchema: %v", err)
	}

	// 2. Both uploaded paths are enforced on top of the startup-loaded spec.
	if !blocked("/api/orders") {
		t.Fatalf("ASSERTION 2 FAILED: an uploaded schema was not enforced on a registry-built layer " +
			"(a request missing the uploaded schema's required parameter `v1` was not blocked)")
	}
	if !blocked("/api/legacy") {
		t.Fatalf("ASSERTION 2b FAILED: the uploaded schema's second path was not enforced " +
			"(a request missing the required parameter `L` was not blocked)")
	}

	// 4. The startup-declared spec keeps being enforced (append semantics for
	//    config sources, which carry no name).
	if !blocked("/api/startup") {
		t.Fatalf("ASSERTION 4 FAILED: the startup-declared schema stopped being enforced after an upload")
	}

	// Direct observable of replacement: the compiled-spec count must not grow
	// on a re-upload under the same name (append semantics would add a spec).
	apiLayer, isAPILayer := eng.FindLayer("apivalidation").(*apivalidation.Layer)
	if !isAPILayer {
		t.Fatalf("harness: apivalidation layer type mismatch")
	}
	specsAfterV1 := apiLayer.GetStats().SpecsLoaded

	// 3. Re-upload under the same name replaces the previous upload. /api/legacy
	//    is gone from v2, so it must stop being enforced.
	if err := adapter.UploadAPISchema("orders", uploadedSpecV2(), "openapi", false); err != nil {
		t.Fatalf("UploadAPISchema (replace): %v", err)
	}
	// The probe must VIOLATE the removed path's old contract (no `L`): a request
	// that satisfies it would pass even while the stale route is still
	// registered, so it cannot distinguish replacement from append.
	if blocked("/api/legacy") {
		t.Fatalf("ASSERTION 3 FAILED: re-uploading under the same name did not replace the previous " +
			"upload — the path /api/legacy, which the new version no longer declares, is still enforced, " +
			"so the replaced spec's stale route survived")
	}
	if blocked("/api/orders?v2=x") {
		t.Fatalf("ASSERTION 3b FAILED: the replacement upload's own contract is not enforced " +
			"(a request satisfying the new required parameter `v2` was blocked)")
	}
	if !blocked("/api/orders?v1=x") {
		t.Fatalf("ASSERTION 3c FAILED: the replaced upload's contract is still enforced " +
			"(a request missing the new required parameter `v2` was not blocked)")
	}
	if specsAfterV2 := apiLayer.GetStats().SpecsLoaded; specsAfterV2 != specsAfterV1 {
		t.Fatalf("ASSERTION 3d FAILED: re-uploading under the same name grew the compiled specs from "+
			"%d to %d — the previous upload was appended, not replaced", specsAfterV1, specsAfterV2)
	}
}

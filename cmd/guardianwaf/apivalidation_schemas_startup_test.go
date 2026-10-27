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
	"github.com/guardianwaf/guardianwaf/internal/runtime/layerregistry"
)

// Regression: `waf.api_validation.schemas` must compile at startup, so a serve
// deployment that declares schemas actually enforces them.
//
// layerregistry.buildAPIValidation maps cfg.WAF.APIValidation.Schemas into
// apivalidation.SchemaSource and hands them to NewLayer — but NewLayer never
// reads cfg.Schemas (it returns a layer with `specs: make([]*CompiledSpec, 0)`),
// and the only production LoadSchema callers are the dashboard and MCP upload
// paths (apivalidation_handlers.go:120/387, mcp_adapter_features.go:284).
// Nothing loads configured schema paths at startup, so a serve deployment that
// declares schemas in YAML runs with ZERO compiled specs:
//   - strict_mode=false → the layer silently passes every request (fail open);
//   - strict_mode=true  → the layer blocks every request ("No OpenAPI schema
//     defined for this endpoint in strict mode") — a self-inflicted outage.
//
// The test builds the layer ONLY through layerregistry.BuildLayer (no
// explicit LoadSchema), exactly as the serve path does.
//
// Assertion 1: with strict_mode=false, a request violating the configured
// request schema must be blocked. Assertion 2: with strict_mode=true, a
// compliant request must not be blocked. Control: with strict_mode=false a
// compliant request passes (must hold before AND after the fix).
const apiSpecYAML = `openapi: 3.0.0
info:
  title: orders
  version: "1.0.0"
paths:
  /api/orders:
    get:
      parameters:
        - name: q
          in: query
          required: true
          schema:
            type: string
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: object
                required:
                  - id
                properties:
                  id:
                    type: integer
`

// specPath must sit under the process working directory: Layer.readFile
// confines schema files to CWD ("path outside allowed directory").
const specPath = "zz_proof_r10_orders_spec.yaml"

func TestDeclaredAPISchemasCompileAtStartup(t *testing.T) {
	if err := os.WriteFile(specPath, []byte(apiSpecYAML), 0o600); err != nil {
		t.Fatalf("write spec: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(specPath) })

	// serveFor builds a real serve-mode engine whose apivalidation layer comes
	// only from the registry, and returns a GET helper against it.
	serveFor := func(strict bool) func(query string) (int, string) {
		cfg := config.DefaultConfig()
		cfg.WAF.APIValidation = config.APIValidationConfig{
			Enabled:          true,
			ValidateRequest:  true,
			ValidateResponse: false,
			StrictMode:       strict,
			BlockOnViolation: true,
			ViolationScore:   40,
			CacheSize:        100,
			Schemas:          []config.SchemaSourceConfig{{Path: specPath, Type: "openapi"}},
		}

		layer, ok, err := layerregistry.BuildLayer("api_validation", cfg)
		if err != nil || !ok {
			t.Fatalf("harness: api_validation layer not built (ok=%v err=%v)", ok, err)
		}
		eng, err := engine.NewEngine(cfg, events.NewMemoryStore(64), events.NewEventBus())
		if err != nil {
			t.Fatalf("engine: %v", err)
		}
		t.Cleanup(func() { _ = eng.Close() })
		eng.AddLayer(layer)

		srv := httptest.NewServer(eng.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"id":42}`)
		})))
		t.Cleanup(srv.Close)

		return func(query string) (int, string) {
			resp, gerr := http.Get(srv.URL + "/api/orders" + query)
			if gerr != nil {
				t.Fatalf("GET %s: %v", query, gerr)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, string(body)
		}
	}

	// Control: strict off, compliant request — passes before and after the fix.
	if status, body := serveFor(false)("?q=x"); status != http.StatusOK {
		t.Fatalf("CONTROL FAILED: a compliant request was blocked with strict_mode=false (status %d, body %.120q)"+
			" — harness problem, not the defect", status, body)
	}
	t.Log("CONTROL PASS: strict off + compliant request passes")

	// Assertion 1: strict off, request violating the configured schema must be blocked.
	if status, body := serveFor(false)(""); status == http.StatusOK {
		t.Fatalf("FAIL: the configured schema in waf.api_validation.schemas was not enforced — a request "+
			"missing the required query parameter `q` passed with status %d (body %.120q). The registry "+
			"maps the declared schemas into apivalidation.Config.Schemas, but NewLayer never reads them "+
			"(specs starts empty) and nothing loads configured schema paths at startup: the only production "+
			"LoadSchema callers are the dashboard and MCP upload paths", status, body)
	}
	t.Log("ASSERTION 1 PASS: the declared schema is enforced (violating request blocked)")

	// Assertion 2: strict on, compliant request must not be blocked (the outage facet).
	if status, body := serveFor(true)("?q=x"); status != http.StatusOK {
		t.Fatalf("FAIL: with strict_mode=true a compliant request was blocked (status %d, body %.120q) "+
			"because the declared schema never compiled and the layer treats zero specs as "+
			"\"no OpenAPI schema defined for this endpoint\" — a total outage for every declared-schema "+
			"deployment", status, body)
	}
	t.Log("ASSERTION 2 PASS: strict on + compliant request passes")
}

package dashboard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/runtime/layerregistry"
)

// Regression: the dashboard's API-validation HTTP routes must work end-to-end
// against a layer built ONLY through layerregistry.BuildLayer (real serve
// wiring), with the same semantics the MCP adapter test pins:
//   - the config-declared schema is enforced;
//   - POST /api/apivalidation/schemas with an upload named after a declared
//     schema REPLACES it (the declared spec's unique path stops being enforced);
//   - DELETE /api/apivalidation/schemas/<name> removes it by identity;
//   - DELETE of an unknown name is an honest 404.
//
// The handler resolves its layer through engine.FindLayer("apivalidation")
// (the production fallback), and requests go through the real route
// registration + authAuditWrap.
const dashDeclaredSpecYAML = `openapi: 3.0.0
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

const dashReplacementSpecYAML = `openapi: 3.0.0
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

func TestAPISchemaHTTPRoutesEnforceAndReplace(t *testing.T) {
	// The declared schema must sit under CWD: Layer.readFile confines schema
	// files to the process working directory.
	const declaredPath = "zz_dash_r13_declared_spec.yaml"
	if err := os.WriteFile(declaredPath, []byte(dashDeclaredSpecYAML), 0o600); err != nil {
		t.Fatalf("write declared spec: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(declaredPath) })

	cfg := config.DefaultConfig()
	cfg.WAF.APIValidation = config.APIValidationConfig{
		Enabled:          true,
		ValidateRequest:  true,
		StrictMode:       false,
		BlockOnViolation: true,
		ViolationScore:   40,
		CacheSize:        100,
		Schemas: []config.SchemaSourceConfig{{
			Path: declaredPath,
			Type: "openapi",
			Name: "orders", // the identity round 12 added
		}},
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

	// Enforcement surface: the same engine the dashboard handler reads its layer from.
	appSrv := httptest.NewServer(eng.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	})))
	t.Cleanup(appSrv.Close)

	get := func(path string) int {
		resp, gerr := http.Get(appSrv.URL + path)
		if gerr != nil {
			t.Fatalf("GET %s: %v", path, gerr)
		}
		defer resp.Body.Close()
		_, _ = io.ReadAll(resp.Body)
		return resp.StatusCode
	}

	// Dashboard HTTP surface: real route registration + auth.
	d := &Dashboard{engine: eng}
	d.apiKey.Store(&apiKeyHolder{Current: "test-key"})
	mux := http.NewServeMux()
	NewAPIValidationHandler(d).RegisterRoutes(mux)
	apiSrv := httptest.NewServer(mux)
	t.Cleanup(apiSrv.Close)

	call := func(method, path, body string) (int, string) {
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, rerr := http.NewRequest(method, apiSrv.URL+path, rdr)
		if rerr != nil {
			t.Fatalf("build request: %v", rerr)
		}
		req.Header.Set("X-API-Key", "test-key")
		req.Header.Set("Content-Type", "application/json")
		resp, derr := http.DefaultClient.Do(req)
		if derr != nil {
			t.Fatalf("%s %s: %v", method, path, derr)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	// Sanity: the config-declared schema is enforced through the real pipeline.
	if get("/api/declared") == http.StatusOK {
		t.Fatalf("harness: the declared schema is not enforced")
	}

	// POST the replacement through the real route: it must replace the declared spec.
	body := `{"name":"orders","content":` + jsonString(dashReplacementSpecYAML) + `,"format":"openapi"}`
	if code, resp := call(http.MethodPost, "/api/apivalidation/schemas", body); code != http.StatusOK {
		t.Fatalf("POST /api/apivalidation/schemas returned %d: %s", code, resp)
	}
	if get("/api/declared-only") != http.StatusOK {
		t.Fatalf("FAIL: the dashboard upload did not replace the declared schema — /api/declared-only, " +
			"declared only by the replaced spec, is still enforced")
	}
	if get("/api/declared") == http.StatusOK {
		t.Fatalf("FAIL: the uploaded schema's own contract is not enforced")
	}

	// DELETE by identity through the real route.
	if code, resp := call(http.MethodDelete, "/api/apivalidation/schemas/orders", ""); code != http.StatusOK {
		t.Fatalf("DELETE /api/apivalidation/schemas/orders returned %d: %s", code, resp)
	}
	if get("/api/declared") != http.StatusOK {
		t.Fatalf("FAIL: DELETE by identity left enforcement behind")
	}

	// Control: DELETE of an unknown name is an honest 404.
	if code, resp := call(http.MethodDelete, "/api/apivalidation/schemas/never-uploaded", ""); code != http.StatusNotFound {
		t.Fatalf("CONTROL FAILED: DELETE of an unknown schema name returned %d (want 404): %s", code, resp)
	}
}

// Regression: the PUT /api/apivalidation/config mode toggles must change
// ENFORCEMENT in the same engine, not just the config read-back.
//
// Engine.Reload explicitly does not rebuild layers ("layers are re-added by the
// caller after reload / This just updates thresholds and config"), and the
// apivalidation layer reads its own construction-time config
// (l.config.ValidateRequest / StrictMode / BlockOnViolation), so a toggle
// applied only to the engine config can leave the layer enforcing the old mode
// while the route reports "updated".
func TestAPISchemaConfigTogglesChangeEnforcement(t *testing.T) {
	const declaredPath = "zz_dash_r14_declared_spec.yaml"
	if err := os.WriteFile(declaredPath, []byte(dashDeclaredSpecYAML), 0o600); err != nil {
		t.Fatalf("write declared spec: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(declaredPath) })

	cfg := config.DefaultConfig()
	cfg.WAF.APIValidation = config.APIValidationConfig{
		Enabled:          true,
		ValidateRequest:  true,
		StrictMode:       false,
		BlockOnViolation: true,
		ViolationScore:   40,
		CacheSize:        100,
		Schemas:          []config.SchemaSourceConfig{{Path: declaredPath, Type: "openapi"}},
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

	appSrv := httptest.NewServer(eng.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	})))
	t.Cleanup(appSrv.Close)

	get := func(path string) int {
		resp, gerr := http.Get(appSrv.URL + path)
		if gerr != nil {
			t.Fatalf("GET %s: %v", path, gerr)
		}
		defer resp.Body.Close()
		_, _ = io.ReadAll(resp.Body)
		return resp.StatusCode
	}
	blocked := func(path string) bool { return get(path) != http.StatusOK }

	d := &Dashboard{engine: eng}
	d.apiKey.Store(&apiKeyHolder{Current: "test-key"})
	mux := http.NewServeMux()
	NewAPIValidationHandler(d).RegisterRoutes(mux)
	apiSrv := httptest.NewServer(mux)
	t.Cleanup(apiSrv.Close)

	put := func(body string) (int, string) {
		req, rerr := http.NewRequest(http.MethodPut, apiSrv.URL+"/api/apivalidation/config", strings.NewReader(body))
		if rerr != nil {
			t.Fatalf("build request: %v", rerr)
		}
		req.Header.Set("X-API-Key", "test-key")
		req.Header.Set("Content-Type", "application/json")
		resp, derr := http.DefaultClient.Do(req)
		if derr != nil {
			t.Fatalf("PUT config: %v", derr)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	// Baseline: the declared schema blocks a violating request, a compliant one passes.
	if !blocked("/api/declared") {
		t.Fatalf("harness: the declared schema is not enforced at baseline")
	}
	if blocked("/api/declared?d=x") {
		t.Fatalf("harness: a compliant request was blocked at baseline")
	}

	// validate_request=false must stop enforcement.
	if code, resp := put(`{"validate_request":false}`); code != http.StatusOK {
		t.Fatalf("PUT validate_request=false returned %d: %s", code, resp)
	}
	if blocked("/api/declared") {
		t.Fatalf("FAIL: PUT /api/apivalidation/config {validate_request:false} was acknowledged but " +
			"enforcement did not change — a request violating the declared schema is still blocked. The " +
			"handler applies the toggle to the engine config and calls engine.Reload, which explicitly " +
			"does not rebuild layers, and the apivalidation layer reads its own construction-time " +
			"l.config.ValidateRequest, so the layer keeps enforcing the old mode")
	}

	// block_on_violation=false must stop blocking while validation still runs.
	if code, resp := put(`{"validate_request":true,"block_on_violation":false}`); code != http.StatusOK {
		t.Fatalf("PUT block_on_violation=false returned %d: %s", code, resp)
	}
	if blocked("/api/declared") {
		t.Fatalf("FAIL: PUT {block_on_violation:false} was acknowledged but the violating request is " +
			"still blocked — the layer still holds its construction-time BlockOnViolation")
	}
	// Round-trip: re-enabling blocking must take effect again.
	if code, resp := put(`{"block_on_violation":true}`); code != http.StatusOK {
		t.Fatalf("PUT block_on_violation=true returned %d: %s", code, resp)
	}
	if !blocked("/api/declared") {
		t.Fatalf("FAIL: PUT {block_on_violation:true} was acknowledged but the violating request is not blocked")
	}

	// strict_mode=true must block routes the schema does not declare.
	if code, resp := put(`{"strict_mode":true}`); code != http.StatusOK {
		t.Fatalf("PUT strict_mode=true returned %d: %s", code, resp)
	}
	if !blocked("/api/not-declared") {
		t.Fatalf("FAIL: PUT {strict_mode:true} was acknowledged but a request to an undeclared route " +
			"is not blocked — the layer still holds its construction-time StrictMode")
	}
	// Control: a compliant request on a declared route still passes.
	if blocked("/api/declared?d=x") {
		t.Fatalf("CONTROL FAILED: a compliant request on a declared route was blocked with strict_mode on")
	}
}

// jsonString encodes s as a JSON string literal.
func jsonString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

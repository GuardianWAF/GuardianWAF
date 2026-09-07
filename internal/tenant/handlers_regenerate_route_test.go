package tenant

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Regression: POST /api/v1/tenants/{id}/regenerate-key returned 405 — the
// regenerate-key subpath was never dispatched. handleTenantRoutes
// special-cased only the /waf-config subpath, so the POST fell into the
// GET/PUT/DELETE method switch, and RegenerateAPIKeyHandler (whose own path
// parsing expects exactly that URL) was unreachable through the router. All
// pre-existing tests invoked the handler method directly, bypassing
// RegisterRoutes, which is why the gap survived.
func TestRegenerateKeyRouteDispatchesThroughRouter(t *testing.T) {
	m := NewManager(10)
	h := NewHandlers(m)
	h.SetAPIKey("route-proof-key")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	do := func(method, path, body string) (*http.Response, []byte) {
		req := httptest.NewRequest(method, path, nil)
		if body != "" {
			req = httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
		}
		req.Header.Set("X-API-Key", "route-proof-key")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Result(), rec.Body.Bytes()
	}

	// Create a tenant through the router.
	res, body := do(http.MethodPost, "/api/v1/tenants",
		`{"name":"regen-route","description":"route regression","domains":["regen-route.test"]}`)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("tenant creation returned %d (body=%s)", res.StatusCode, body)
	}
	var created struct {
		Tenant struct {
			ID string `json:"id"`
		} `json:"tenant"`
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decoding create response: %v", err)
	}
	if created.Tenant.ID == "" || created.APIKey == "" {
		t.Fatalf("unexpected create response: %s", body)
	}

	// Regenerate through the router: 200 + rotated key.
	res, body = do(http.MethodPost, "/api/v1/tenants/"+created.Tenant.ID+"/regenerate-key", "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("POST regenerate-key returned %d, want 200 (body=%s)", res.StatusCode, body)
	}
	var regenerated struct {
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal(body, &regenerated); err != nil {
		t.Fatalf("decoding regenerate response: %v", err)
	}
	if regenerated.APIKey == "" {
		t.Fatalf("regenerate response carried no api_key")
	}
	if regenerated.APIKey == created.APIKey {
		t.Fatalf("api key was not rotated")
	}

	// Boundary: GET on the regenerate-key subpath must still be rejected by
	// the handler's own method check (dispatch reaches it now).
	if res, _ = do(http.MethodGet, "/api/v1/tenants/"+created.Tenant.ID+"/regenerate-key", ""); res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET regenerate-key returned %d, want 405", res.StatusCode)
	}

	// Boundary: unauthorized requests are rejected before dispatch.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+created.Tenant.ID+"/regenerate-key", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized regenerate returned %d, want 401", rec.Code)
	}
}

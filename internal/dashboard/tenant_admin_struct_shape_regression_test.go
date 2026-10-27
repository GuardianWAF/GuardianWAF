package dashboard

// Regression: the admin invoice-generation endpoint rejected every REAL tenant.
//
// handleBillingDetail type-asserted the tenantManagerInterface.GetTenant result
// to map[string]any. Production returns a *tenant.Tenant STRUCT (see
// cmd/guardianwaf/dashboard_adapters.go), so the assertion always failed and
// POST /api/admin/billing/{tenantID} returned 500 "invalid tenant data" for
// every tenant. The endpoint was unreachable in production.
//
// It went unnoticed because every dashboard test mock returns map[string]any —
// the one shape the bare assertion accepted. The handler's own sibling helpers
// (decodeTenantAuthRecord, sanitizeTenantResponse) already JSON-round-trip
// precisely because "production managers return structs while tests and
// integrations may return maps".
//
// These tests drive the real registered route with a manager that returns the
// production STRUCT shape.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// structShapedTenant mirrors the JSON tags of internal/tenant.Tenant — the shape
// the production tenantManagerAdapter returns. Deliberately a struct, not a map.
type structShapedTenant struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	BillingPlan string `json:"billing_plan"`
	APIKeyHash  string `json:"api_key_hash"`
}

// structTenantManager returns struct-shaped tenants from GetTenant, matching
// production. The package's other mocks assert map[string]any internally, so
// they can never represent this shape and cannot catch this defect.
type structTenantManager struct {
	fullMockTenantManager // reuse the 16-method interface impl

	structTenant *structShapedTenant
}

func (m *structTenantManager) GetTenant(id string) any {
	if m.structTenant != nil && m.structTenant.ID == id {
		return m.structTenant
	}
	// Fall back to the embedded mock's map-shaped tenants.
	return m.fullMockTenantManager.GetTenant(id)
}

func (m *structTenantManager) BillingManager() BillingManagerInterface {
	if m.fullMockTenantManager.billing != nil {
		return m.fullMockTenantManager.billing
	}
	return &mockBillingManager{invoices: []any{map[string]any{"id": "inv-struct"}}}
}

func newStructTenantHandler(t *testing.T) *TenantAdminHandler {
	t.Helper()
	d := newTestDashboard(t, "admin-key")
	d.SetAdminKey("admin-key")
	mgr := &structTenantManager{
		fullMockTenantManager: fullMockTenantManager{
			billing: &mockBillingManager{invoices: []any{map[string]any{"id": "inv-struct"}}},
			alerts:  &mockAlertManagerForTenant{alerts: []any{}},
			usage:   []any{map[string]any{"tenant_id": "s1", "requests": 1}},
		},
		structTenant: &structShapedTenant{
			ID:          "s1",
			Name:        "Struct Tenant",
			BillingPlan: "enterprise",
			APIKeyHash:  "must-not-leak",
		},
	}
	return NewTenantAdminHandler(d, mgr)
}

func postBillingDetail(t *testing.T, h *TenantAdminHandler, tenantID string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/billing/"+tenantID, nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleBillingDetail(rr, req)
	return rr
}

// TestTenantBillingDetail_PostAcceptsStructShapedTenant is the defect
// assertion: a tenant returned as a STRUCT (the production shape) must reach
// GenerateInvoice instead of being rejected as "invalid tenant data".
func TestTenantBillingDetail_PostAcceptsStructShapedTenant(t *testing.T) {
	h := newStructTenantHandler(t)

	rr := postBillingDetail(t, h, "s1")

	if rr.Code != http.StatusCreated {
		t.Fatalf("invoice generation must accept the production struct-shaped tenant and return 201; got %d: %s",
			rr.Code, rr.Body.String())
	}

	// The plan must come from the struct's billing_plan JSON tag — this proves
	// the value was actually decoded through JSON tags, not merely that the
	// request no longer errored.
	var invoice map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &invoice); err != nil {
		t.Fatalf("HARNESS FAIL: invoice response is not JSON: %v (body=%s)", err, rr.Body.String())
	}
	if invoice["plan"] != "enterprise" {
		t.Fatalf("plan must be decoded from the struct's billing_plan JSON tag; got %v", invoice["plan"])
	}
	if invoice["tenant_id"] != "s1" {
		t.Fatalf("invoice must be generated for tenant s1; got %v", invoice["tenant_id"])
	}
}

// TestTenantBillingDetail_PostAcceptsMapShapedTenant is the control: the
// map-shaped tenant the package's other mocks return must keep working, so the
// fix did not narrow the accepted shapes.
func TestTenantBillingDetail_PostAcceptsMapShapedTenant(t *testing.T) {
	h := newTenantHandlerWithFullMocks(t)

	rr := postBillingDetail(t, h, "t1")

	if rr.Code != http.StatusCreated {
		t.Fatalf("map-shaped tenants must keep working after the fix; got %d: %s", rr.Code, rr.Body.String())
	}
	var invoice map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &invoice); err != nil {
		t.Fatalf("HARNESS FAIL: invoice response is not JSON: %v", err)
	}
	if invoice["plan"] != "pro" {
		t.Fatalf("plan must come from the map's billing_plan; got %v", invoice["plan"])
	}
}

// TestTenantBillingDetail_PostUnknownTenantStill404 is the secondary branch the
// fix must not disturb: an unknown tenant is a 404, not a 500.
func TestTenantBillingDetail_PostUnknownTenantStill404(t *testing.T) {
	h := newStructTenantHandler(t)

	rr := postBillingDetail(t, h, "does-not-exist")

	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown tenant must return 404; got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestTenantToJSONMap covers the helper directly, including the non-object
// shapes that must still be reported as not-representable.
func TestTenantToJSONMap(t *testing.T) {
	t.Run("struct", func(t *testing.T) {
		m, ok := tenantToJSONMap(&structShapedTenant{ID: "x", Name: "n", BillingPlan: "pro"})
		if !ok || m["billing_plan"] != "pro" {
			t.Fatalf("struct must convert; ok=%v map=%v", ok, m)
		}
	})
	t.Run("map", func(t *testing.T) {
		m, ok := tenantToJSONMap(map[string]any{"id": "x"})
		if !ok || m["id"] != "x" {
			t.Fatalf("map must convert; ok=%v map=%v", ok, m)
		}
	})
	t.Run("nil rejected", func(t *testing.T) {
		if _, ok := tenantToJSONMap(nil); ok {
			t.Fatal("nil tenant must not convert")
		}
	})
	t.Run("non-object rejected", func(t *testing.T) {
		if _, ok := tenantToJSONMap("a bare string"); ok {
			t.Fatal("a JSON scalar is not a tenant object and must not convert")
		}
	})
}

// keep the time import honest: the handler builds a one-month billing window.
var _ = time.Now

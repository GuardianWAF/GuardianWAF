package dashboard

// Regression tests: handleBillingDetail must answer the "multi-tenant enabled
// but billing disabled" state (BillingManager() == nil) with 503 "billing not
// enabled", exactly like its sibling handleBilling. The previous guard checked
// only h.manager == nil, so every GET/POST to /api/admin/billing/{tenantID}
// panicked the handler goroutine on a nil-interface method call in that
// supported configuration.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type billingNilStub struct {
	tenantManagerInterface
}

func (s *billingNilStub) BillingManager() BillingManagerInterface { return nil }
func (s *billingNilStub) AlertManager() AlertManagerInterface     { return nil }

func TestTenantBillingDetailNilBillingManager(t *testing.T) {
	h := &TenantAdminHandler{dashboard: &Dashboard{}, manager: &billingNilStub{}}

	// Sibling control: handleBilling answers the disabled-billing state with 503.
	rec := httptest.NewRecorder()
	h.handleBilling(rec, httptest.NewRequest(http.MethodGet, "/api/admin/billing", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("handleBilling returned %d, want 503 for disabled billing", rec.Code)
	}

	// handleBillingDetail must not panic and must return the same 503.
	rec2 := httptest.NewRecorder()
	h.handleBillingDetail(rec2, httptest.NewRequest(http.MethodGet, "/api/admin/billing/tenant-1", nil))
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("handleBillingDetail returned %d, want 503 \"billing not enabled\" — consistent with handleBilling", rec2.Code)
	}

	// The POST path takes the same guard before any BillingManager use.
	rec3 := httptest.NewRecorder()
	h.handleBillingDetail(rec3, httptest.NewRequest(http.MethodPost, "/api/admin/billing/tenant-1", nil))
	if rec3.Code != http.StatusServiceUnavailable {
		t.Fatalf("handleBillingDetail (POST) returned %d, want 503", rec3.Code)
	}
}

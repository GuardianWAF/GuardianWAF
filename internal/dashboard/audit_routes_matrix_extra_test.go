package dashboard

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRemainingManagementMutationRoutesAreAudited complements the primary
// route matrix with every additional method/path variant exposed by generic
// per-layer and administrator handlers. Invalid credentials exercise the real
// ServeMux while avoiding mutation of test state.
func TestRemainingManagementMutationRoutesAreAudited(t *testing.T) {
	d := newTestDashboard(t, "dashboard-key")
	d.SetAdminKey("admin-key")
	t.Cleanup(d.Close)

	tests := []struct {
		method string
		path   string
		action string
	}{
		{http.MethodPut, "/api/v1/config/bot", "update_config_subresource"},
		{http.MethodPost, "/api/v1/ai/test", "ai_operation"},
		{http.MethodPost, "/api/v1/alerting/emails", "add_email"},
		{http.MethodDelete, "/api/v1/alerting/emails/ops", "delete_email"},
		{http.MethodPost, "/api/v1/alerting/test", "test_alert"},
		{http.MethodPost, "/api/v1/rotate-key", "rotate_api_key"},
		{http.MethodPost, "/api/clusters/cluster-1", "cluster_mutation"},
		{http.MethodDelete, "/api/clusters/cluster-1", "cluster_mutation"},
		{http.MethodPut, "/api/crs/rules/942100", "crs_mutation"},
		{http.MethodDelete, "/api/dlp/patterns/custom-1", "dlp_mutation"},
		{http.MethodPost, "/api/clientside/skimming-domains", "clientside_mutation"},
		{http.MethodDelete, "/api/apivalidation/schemas/openapi", "api_validation_mutation"},
		{http.MethodPut, "/api/apivalidation/config", "api_validation_mutation"},
		{http.MethodPut, "/api/virtualpatch/patches/CVE-2026-0001", "virtual_patch_mutation"},
		{http.MethodDelete, "/api/virtualpatch/patches/CVE-2026-0001", "virtual_patch_mutation"},
		{http.MethodPost, "/api/virtualpatch/update", "virtual_patch_mutation"},
		{http.MethodPut, "/api/admin/tenants/tenant-1", "admin_tenant_mutation"},
		{http.MethodDelete, "/api/admin/tenants/tenant-1", "admin_tenant_mutation"},
		{http.MethodPost, "/api/admin/tenants/tenant-1/regenerate-key", "admin_tenant_mutation"},
		{http.MethodPut, "/api/admin/tenants/rules/tenant-1/rule-1", "admin_tenant_rule_mutation"},
		{http.MethodPatch, "/api/admin/tenants/rules/tenant-1/rule-1", "admin_tenant_rule_mutation"},
		{http.MethodDelete, "/api/admin/tenants/rules/tenant-1/rule-1", "admin_tenant_rule_mutation"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			before := d.auditLog.Len()
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.Header.Set("X-API-Key", "invalid-key")
			w := httptest.NewRecorder()
			d.Handler().ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
			}
			if got := d.auditLog.Len(); got != before+1 {
				t.Fatalf("audit entries = %d, want %d", got, before+1)
			}
			entry := d.auditLog.Recent(1)[0]
			if entry.Method != tt.method || entry.Path != tt.path || entry.Mutation != tt.action ||
				entry.Status != http.StatusUnauthorized || entry.AuthType != "unauthenticated" ||
				entry.Principal != "unauthenticated" {
				t.Fatalf("unexpected audit entry: %+v", entry)
			}
		})
	}
}

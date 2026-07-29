package dashboard

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestManagementMutationRoutesAreAudited is the executable inventory of
// dashboard state-changing routes. An invalid credential must be rejected by
// the real ServeMux and still produce exactly one audit record.
func TestManagementMutationRoutesAreAudited(t *testing.T) {
	d := newTestDashboard(t, "dashboard-key")
	d.SetAdminKey("admin-key")
	t.Cleanup(d.Close)

	tests := []struct {
		method string
		path   string
		action string
	}{
		{http.MethodPut, "/api/v1/config", "update_config"},
		{http.MethodPut, "/api/v1/config/ratelimit", "update_config_subresource"},
		{http.MethodPost, "/api/v1/config/reload", "reload_config"},
		{http.MethodPost, "/api/v1/rules", "add_rule"},
		{http.MethodPut, "/api/v1/rules/rule-1", "update_rule"},
		{http.MethodPatch, "/api/v1/rules/rule-1", "toggle_rule"},
		{http.MethodDelete, "/api/v1/rules/rule-1", "delete_rule"},
		{http.MethodPut, "/api/v1/routing", "update_routing"},
		{http.MethodPost, "/api/v1/ipacl", "add_ip_acl"},
		{http.MethodDelete, "/api/v1/ipacl", "remove_ip_acl"},
		{http.MethodPost, "/api/v1/bans", "add_ban"},
		{http.MethodDelete, "/api/v1/bans", "remove_ban"},
		{http.MethodPut, "/api/v1/ai/config", "update_ai_config"},
		{http.MethodPost, "/api/v1/ai/analyze", "ai_operation"},
		{http.MethodPost, "/api/v1/alerts", "add_alert"},
		{http.MethodPut, "/api/v1/alerts/alert-1", "update_alert"},
		{http.MethodDelete, "/api/v1/alerts/alert-1", "delete_alert"},
		{http.MethodPost, "/api/v1/alerting/webhooks", "add_webhook"},
		{http.MethodDelete, "/api/v1/alerting/webhooks/ops", "delete_webhook"},
		{http.MethodPost, "/api/v1/ssl/certificates", "upload_certificate"},
		{http.MethodDelete, "/api/v1/ssl/certificates/example", "delete_certificate"},
		{http.MethodPost, "/api/v1/tenants", "create_tenant"},
		{http.MethodPut, "/api/v1/tenants/tenant-1", "update_tenant"},
		{http.MethodDelete, "/api/v1/tenants/tenant-1", "delete_tenant"},
		{http.MethodPut, "/api/v1/tenants/tenant-1/config", "update_tenant_config"},
		{http.MethodPost, "/api/v1/tenants/tenant-1/apikey", "rotate_tenant_api_key"},
		{http.MethodPost, "/api/clusters", "cluster_mutation"},
		{http.MethodPut, "/api/crs/config", "crs_mutation"},
		{http.MethodPost, "/api/dlp/patterns", "dlp_mutation"},
		{http.MethodPut, "/api/clientside/config", "clientside_mutation"},
		{http.MethodPost, "/api/apivalidation/schemas", "api_validation_mutation"},
		{http.MethodPost, "/api/virtualpatch/patches", "virtual_patch_mutation"},
		{http.MethodPost, "/api/admin/tenants", "admin_tenant_mutation"},
		{http.MethodPost, "/api/admin/tenants/rules", "admin_tenant_rule_mutation"},
		{http.MethodPost, "/api/admin/billing/tenant-1", "generate_invoice"},
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

func TestNonManagementPostRoutesAreNotAudited(t *testing.T) {
	d := newTestDashboard(t, "dashboard-key")
	t.Cleanup(d.Close)

	for _, path := range []string{
		"/api/v1/cwv",
		"/api/v1/geoip/lookup",
		"/api/crs/test",
		"/api/dlp/test",
		"/api/apivalidation/test",
	} {
		t.Run(path, func(t *testing.T) {
			before := d.auditLog.Len()
			req := httptest.NewRequest(http.MethodPost, path, nil)
			req.Header.Set("X-API-Key", "invalid-key")
			w := httptest.NewRecorder()
			d.Handler().ServeHTTP(w, req)
			if got := d.auditLog.Len(); got != before {
				t.Fatalf("non-management route created audit entry: before=%d after=%d", before, got)
			}
		})
	}
}

func TestMutationAuditIdentityAcrossAuthorizationOutcomes(t *testing.T) {
	d := newTestDashboard(t, "dashboard-key")
	d.SetAdminKey("admin-key")
	d.SetTenantAPIKey("tenant-1", legacyTenantKeyHash("tenant-key"))
	t.Cleanup(d.Close)

	tests := []struct {
		name      string
		method    string
		path      string
		key       string
		wantCode  int
		wantAuth  string
		principal string
	}{
		{"global key accepted", http.MethodPost, "/api/clusters", "dashboard-key", http.StatusServiceUnavailable, authGlobalKey, "admin"},
		{"tenant key forbidden", http.MethodPost, "/api/v1/rules", "tenant-key", http.StatusForbidden, authTenant, "tenant-1"},
		{"admin key accepted", http.MethodPost, "/api/admin/tenants", "admin-key", http.StatusServiceUnavailable, "admin_key", "admin"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.Header.Set("X-API-Key", tt.key)
			if tt.wantAuth == authTenant {
				req.Header.Set("X-Tenant-ID", "tenant-1")
			}
			w := httptest.NewRecorder()
			d.Handler().ServeHTTP(w, req)
			if w.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d", w.Code, tt.wantCode)
			}
			entry := d.auditLog.Recent(1)[0]
			if entry.AuthType != tt.wantAuth || entry.Principal != tt.principal || entry.Status != tt.wantCode {
				t.Fatalf("unexpected audit identity: %+v", entry)
			}
		})
	}
}

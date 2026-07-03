package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

func TestTenantRuntimeDefaults(t *testing.T) {
	if got := tenantMaxTenants(0); got != defaultTenantMaxTenants {
		t.Fatalf("tenantMaxTenants(0) = %d, want %d", got, defaultTenantMaxTenants)
	}
	if got := tenantMaxTenants(-10); got != defaultTenantMaxTenants {
		t.Fatalf("tenantMaxTenants(-10) = %d, want %d", got, defaultTenantMaxTenants)
	}
	if got := tenantMaxTenants(7); got != 7 {
		t.Fatalf("tenantMaxTenants(7) = %d, want 7", got)
	}
	if got := tenantStorePath(""); got != defaultTenantStorePath {
		t.Fatalf("tenantStorePath(\"\") = %q, want %q", got, defaultTenantStorePath)
	}
	if got := tenantStorePath("/tmp/tenants"); got != "/tmp/tenants" {
		t.Fatalf("tenantStorePath custom = %q", got)
	}
}

func TestTenantResourceQuota(t *testing.T) {
	quota := tenantResourceQuota(config.ResourceQuotaConfig{
		MaxRequestsPerMinute: 11,
		MaxRequestsPerHour:   22,
		MaxBandwidthMbps:     33,
		MaxRules:             44,
		MaxRateLimitRules:    55,
		MaxIPACLs:            66,
	})

	if quota.MaxRequestsPerMinute != 11 ||
		quota.MaxRequestsPerHour != 22 ||
		quota.MaxBandwidthMbps != 33 ||
		quota.MaxRules != 44 ||
		quota.MaxRateLimitRules != 55 ||
		quota.MaxIPACLs != 66 {
		t.Fatalf("unexpected quota conversion: %+v", quota)
	}
}

func TestSetupTenantRuntimeDisabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Tenant.Enabled = false

	var upstream atomic.Value
	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	upstream.Store(baseHandler)

	tenantManager, tenantMiddleware := setupTenantRuntime(cfg, nil, nil, &upstream, nil)
	if tenantManager != nil || tenantMiddleware != nil {
		t.Fatalf("disabled tenant runtime returned manager=%v middleware=%v", tenantManager, tenantMiddleware)
	}
	if got := loadHTTPHandler(&upstream); got == nil {
		t.Fatal("disabled tenant runtime removed the upstream handler")
	}
}

func TestSetupTenantRuntimeCreatesManagerAndWrapsHandler(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Tenant.Enabled = true
	cfg.Tenant.StorePath = t.TempDir()
	cfg.Tenant.Tenants = []config.TenantDefinition{{
		Name:        "Acme",
		Description: "Acme tenant",
		Domains:     []string{"acme.test"},
		Quota: config.ResourceQuotaConfig{
			MaxRequestsPerMinute: 100,
			MaxRequestsPerHour:   1000,
			MaxBandwidthMbps:     10,
			MaxRules:             20,
			MaxRateLimitRules:    3,
			MaxIPACLs:            40,
		},
	}}

	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	var upstream atomic.Value
	upstream.Store(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if engine.GetTenantContext(r.Context()) == nil {
			t.Error("expected engine tenant context")
		}
		w.WriteHeader(http.StatusAccepted)
	}))

	tenantManager, tenantMiddleware := setupTenantRuntime(cfg, eng, nil, &upstream, nil)
	if tenantManager == nil {
		t.Fatal("expected tenant manager")
	}
	if tenantMiddleware == nil {
		t.Fatal("expected tenant middleware")
	}
	if got := tenantManager.GetTenantByDomain("acme.test"); got == nil {
		t.Fatal("expected configured tenant to be created")
	}

	req := httptest.NewRequest(http.MethodGet, "http://acme.test/", nil)
	rec := httptest.NewRecorder()
	loadHTTPHandler(&upstream).ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("wrapped handler status = %d, want %d", rec.Code, http.StatusAccepted)
	}
}

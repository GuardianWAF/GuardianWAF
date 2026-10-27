package tenant

// Regression tests: getTenantWAFConfig must read tenant.Config under
// tenant.mu.
//
// The handler read `tenant.Config` with no lock, while UpdateTenant publishes
// that field under tenant.mu (manager.go). A concurrent authenticated GET of
// /api/v1/tenants/{id}/waf-config and PUT of the same path therefore raced on
// the pointer field — the race detector reported it directly.
//
// This file's siblings already encode the rule the handler broke:
// updateTenantWAFConfig (handlers.go) takes tenant.mu.RLock around exactly this
// read and documents why, and sanitizeTenant holds t.mu.RLock and copies Quota
// for the same reason. Only the POINTER is read under the lock; UpdateTenant
// replaces the pointer and never mutates a config in place, so dereferencing
// the captured pointer afterwards stays safe.
//
// The assertions are the race detector's: under `go test -race` a conflicting
// access fails the package. Each test also asserts ordinary behaviour, so a
// harness or routing fault cannot masquerade as the regression.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// wcfgAdminKey is a test fixture, not a credential: the Handlers API key the
// tests authenticate with. Production wiring supplies the real key.
const wcfgAdminKey = "test-admin-key"

// wcfgManager returns a Manager whose tenant store is a fresh temp dir. The
// package default (data/tenants) persists across runs, so a leftover store
// would preload tenants and make these tests depend on unrelated state.
func wcfgManager(t *testing.T) *Manager {
	t.Helper()
	m := NewManagerWithStore(10, filepath.Join(t.TempDir(), "tenants"))
	if err := m.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(m.Close)
	if got := len(m.ListTenants()); got != 0 {
		t.Fatalf("expected an empty manager, got %d tenants", got)
	}
	return m
}

// wcfgMux wires the real Handlers through their real route registration.
func wcfgMux(t *testing.T, m *Manager) *http.ServeMux {
	t.Helper()
	h := NewHandlers(m)
	h.SetAPIKey(wcfgAdminKey)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux
}

func wcfgReq(method, path, body string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	r.Header.Set("X-API-Key", wcfgAdminKey)
	return r
}

// wcfgPutBody builds a distinct WAF config per call so UpdateTenant genuinely
// publishes a new *config.Config pointer each time.
func wcfgPutBody(t *testing.T, i int) string {
	t.Helper()
	b, err := json.Marshal(config.WAFConfig{
		Detection: config.DetectionConfig{
			Enabled:   true,
			Threshold: config.ThresholdConfig{Block: 50 + i, Log: 25 + i},
		},
	})
	if err != nil {
		t.Fatalf("marshal WAF config: %v", err)
	}
	return string(b)
}

// The defect: a WAF-config GET concurrent with a WAF-config PUT races on
// tenant.Config. Under -race the conflicting read/write fails this test.
func TestGetTenantWAFConfigReadIsRaceFreeUnderConcurrentUpdate(t *testing.T) {
	m := wcfgManager(t)
	mux := wcfgMux(t, m)

	tenant, err := m.CreateTenant("acme", "race", []string{"race.example.com"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	cfgPath := "/api/v1/tenants/" + tenant.ID + "/waf-config"

	// Pre-flight: confirm a PUT really publishes a new pointer, so the
	// concurrent GET below races a real publication rather than a no-op.
	before := m.GetTenant(tenant.ID).Config
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, wcfgReq(http.MethodPut, cfgPath, wcfgPutBody(t, 1)))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT waf-config returned %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if m.GetTenant(tenant.ID).Config == before {
		t.Fatalf("precondition failed: PUT did not publish a new tenant.Config pointer")
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 400; i++ {
			select {
			case <-stop:
				return
			default:
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, wcfgReq(http.MethodGet, cfgPath, ""))
		}
	}()
	for i := 0; i < 400; i++ {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, wcfgReq(http.MethodPut, cfgPath, wcfgPutBody(t, i+2)))
	}
	close(stop)
	wg.Wait()
}

// The single-threaded read must still return this tenant's config, and a PUT
// must be visible to the manager afterwards.
func TestGetTenantWAFConfigReturnsOwnConfig(t *testing.T) {
	m := wcfgManager(t)
	mux := wcfgMux(t, m)

	tenant, err := m.CreateTenant("acme", "read", []string{"read.example.com"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	cfgPath := "/api/v1/tenants/" + tenant.ID + "/waf-config"

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, wcfgReq(http.MethodGet, cfgPath, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET waf-config returned %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var got config.Config
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("GET waf-config did not return valid JSON: %v", err)
	}

	putRec := httptest.NewRecorder()
	mux.ServeHTTP(putRec, wcfgReq(http.MethodPut, cfgPath, wcfgPutBody(t, 7)))
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT waf-config returned %d, want 200 (body=%s)", putRec.Code, putRec.Body.String())
	}
	if got := m.GetTenant(tenant.ID).Config.WAF.Detection.Threshold.Block; got != 57 {
		t.Fatalf("PUT did not publish the WAF block threshold (got %d, want 57)", got)
	}
}

// The sibling PUT path must stay race-free after the fix — both handlers read
// the same field and must both hold the lock.
func TestUpdateTenantWAFConfigReadRemainsRaceFree(t *testing.T) {
	m := wcfgManager(t)
	mux := wcfgMux(t, m)

	tenant, err := m.CreateTenant("acme", "both", []string{"both.example.com"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	cfgPath := "/api/v1/tenants/" + tenant.ID + "/waf-config"

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 400; i++ {
			select {
			case <-stop:
				return
			default:
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, wcfgReq(http.MethodPut, cfgPath, wcfgPutBody(t, i)))
		}
	}()
	for i := 0; i < 400; i++ {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, wcfgReq(http.MethodGet, cfgPath, ""))
	}
	close(stop)
	wg.Wait()

	if m.GetTenant(tenant.ID) == nil {
		t.Fatalf("tenant %s disappeared during concurrent access", tenant.ID)
	}
}

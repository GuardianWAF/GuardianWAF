package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/dashboard"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/tenant"
)

func productionTenantFixture(t *testing.T) (*tenant.Manager, *dashboard.Dashboard, string, string) {
	t.Helper()
	m := tenant.NewManagerWithStore(10, t.TempDir())
	t.Cleanup(m.Close)
	if err := m.Init(); err != nil {
		t.Fatal(err)
	}
	ten, err := m.CreateTenant("audit", "", []string{"audit.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	old, err := m.RegenerateAPIKey(ten.ID)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := engine.NewEngine(config.DefaultConfig(), events.NewMemoryStore(20), events.NewEventBus())
	if err != nil {
		t.Fatal(err)
	}
	d := dashboard.New(eng, events.NewMemoryStore(20), "global-audit-key-0001")
	t.Cleanup(d.Close)
	d.SetAdminKey("admin-audit-key-0001")
	d.SetTenantManager(&tenantManagerAdapter{mgr: m})
	return m, d, ten.ID, old
}

func TestProductionTenantLiveAuthentication(t *testing.T) {
	m, d, id, old := productionTenantFixture(t)
	// Mutate through the manager, deliberately bypassing all dashboard refresh
	// callbacks. A copied dashboard snapshot must never resurrect this key.
	key, err := m.RegenerateAPIKey(id)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		key  string
		want int
	}{{old, 401}, {key, 200}, {"", 401}} {
		if got := productionTenantRequest(d, "GET", "/api/v1/events", "", tc.key, id); got.Code != tc.want {
			t.Fatalf("key auth status=%d want=%d", got.Code, tc.want)
		}
	}
	active := false
	if err := m.UpdateTenant(id, &tenant.TenantUpdate{Active: &active}); err != nil {
		t.Fatal(err)
	}
	if got := productionTenantRequest(d, "GET", "/api/v1/events", "", key, id); got.Code != 401 {
		t.Fatalf("inactive tenant authenticated: %d", got.Code)
	}
	active = true
	if err := m.UpdateTenant(id, &tenant.TenantUpdate{Active: &active}); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteTenant(id); err != nil {
		t.Fatal(err)
	}
	if got := productionTenantRequest(d, "GET", "/api/v1/events", "", key, id); got.Code != 401 {
		t.Fatalf("deleted tenant authenticated: %d", got.Code)
	}
}

func TestProductionTenantConfigPatchValidation(t *testing.T) {
	m, d, id, _ := productionTenantFixture(t)
	key := "admin-audit-key-0001"
	for _, body := range []string{
		`{"sanitizer":{"max_body_size":4096}}`,
		`{"detection":{"threshold":{"block":75}}}`,
		`{}`,
	} {
		if r := productionTenantRequest(d, "PUT", "/api/v1/tenants/"+id+"/config", body, key, ""); r.Code != 200 {
			t.Fatalf("valid patch %s: %d %s", body, r.Code, r.Body.String())
		}
	}
	cfg := m.GetTenant(id).Config
	if cfg.WAF.Sanitizer.MaxBodySize != 4096 || cfg.WAF.Detection.Threshold.Block != 75 || !cfg.WAF.Detection.Enabled {
		t.Fatal("patch lost specified or unspecified config values")
	}
	for _, body := range []string{
		`{"detection":{"enabled":"false"}}`,
		`{"sanitizer":{"max_body_size":1.5}}`,
		`{"detection":{"typo":false}}`,
		`{"sanitizer":null}`,
	} {
		if r := productionTenantRequest(d, "PUT", "/api/v1/tenants/"+id+"/config", body, key, ""); r.Code != 400 {
			t.Fatalf("invalid patch %s: %d %s", body, r.Code, r.Body.String())
		}
	}
	cfg = m.GetTenant(id).Config
	if cfg.WAF.Sanitizer.MaxBodySize != 4096 || cfg.WAF.Detection.Threshold.Block != 75 {
		t.Fatal("rejected patch changed config")
	}
}

func TestProductionTenantUnsupportedRotationSettings(t *testing.T) {
	_, d, id, _ := productionTenantFixture(t)
	for _, prefix := range []string{"/api/v1/tenants/", "/api/admin/tenants/"} {
		for _, body := range []string{`{"auto_rotation":true}`, `{"rotation_interval":"90days"}`} {
			if r := productionTenantRequest(d, "PUT", prefix+id, body, "admin-audit-key-0001", ""); r.Code != 400 {
				t.Fatalf("unsupported setting %s %s: %d", prefix, body, r.Code)
			}
		}
	}
}
func productionTenantRequest(d *dashboard.Dashboard, method, path, body, key, id string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", key)
	if id != "" {
		req.Header.Set("X-Tenant-ID", id)
	}
	rr := httptest.NewRecorder()
	d.Handler().ServeHTTP(rr, req)
	return rr
}
func TestProductionTenantCompatibilityRotationRevokesKey(t *testing.T) {
	m, d, id, old := productionTenantFixture(t)
	control := productionTenantRequest(d, "GET", "/api/v1/events", "", old, id)
	if control.Code != 200 {
		t.Fatalf("control old key before rotation=%d %s", control.Code, control.Body.String())
	}
	rotated := productionTenantRequest(d, "POST", "/api/v1/tenants/"+id+"/apikey", "", "admin-audit-key-0001", "")
	if rotated.Code != 200 {
		t.Fatalf("rotation=%d %s", rotated.Code, rotated.Body.String())
	}
	var data struct {
		Key string `json:"api_key"`
	}
	if err := json.Unmarshal(rotated.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if data.Key == "" || m.GetTenantByAPIKey(data.Key) == nil || m.GetTenantByAPIKey(old) != nil {
		t.Fatal("manager control failed")
	}
	oldResult := productionTenantRequest(d, "GET", "/api/v1/events", "", old, id)
	newResult := productionTenantRequest(d, "GET", "/api/v1/events", "", data.Key, id)
	if oldResult.Code != 401 || newResult.Code != 200 {
		t.Fatal("PROBLEM CONFIRMED: dashboard accepts revoked tenant key after compatibility rotation")
	}
}
func TestProductionTenantConfigPatchApplies(t *testing.T) {
	m, d, id, _ := productionTenantFixture(t)
	control := productionTenantRequest(d, "PUT", "/api/v1/tenants/"+id, `{"name":"control-updated"}`, "admin-audit-key-0001", "")
	if control.Code != 200 || m.GetTenant(id).Name != "control-updated" {
		t.Fatal("control name update failed")
	}
	r := productionTenantRequest(d, "PUT", "/api/v1/tenants/"+id+"/config", `{"detection":{"enabled":false}}`, "admin-audit-key-0001", "")
	if r.Code != 200 {
		t.Fatalf("request status=%d %s", r.Code, r.Body.String())
	}
	if m.GetTenant(id).Config.WAF.Detection.Enabled {
		t.Fatal("PROBLEM CONFIRMED: successful tenant WAF config mutation is discarded by real adapter")
	}
}
func TestProductionTenantRotationPersistenceFailure(t *testing.T) {
	path := t.TempDir()
	m := tenant.NewManagerWithStore(10, path)
	t.Cleanup(m.Close)
	if err := m.Init(); err != nil {
		t.Fatal(err)
	}
	ten, err := m.CreateTenant("durable", "", []string{"durable.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	old, err := m.RegenerateAPIKey(ten.ID)
	if err != nil {
		t.Fatal(err)
	}
	control := tenant.NewManagerWithStore(10, path)
	t.Cleanup(control.Close)
	if err := control.Init(); err != nil {
		t.Fatal(err)
	}
	if control.GetTenantByAPIKey(old) == nil {
		t.Fatal("control durable old key failed")
	}
	// A directory at the fixed temporary pathname deterministically injects a real write failure.
	if err := os.Mkdir(filepath.Join(path, ten.ID+".json.tmp"), 0700); err != nil {
		t.Fatal(err)
	}
	newKey, rotateErr := m.RegenerateAPIKey(ten.ID)
	if rotateErr == nil || newKey != "" {
		t.Fatal("rotation must report failed persistence without returning a key")
	}
	if m.GetTenantByAPIKey(old) == nil {
		t.Fatal("failed rotation must preserve live credentials")
	}
	restarted := tenant.NewManagerWithStore(10, path)
	t.Cleanup(restarted.Close)
	if err := restarted.Init(); err != nil {
		t.Fatal(err)
	}
	if restarted.GetTenantByAPIKey(old) == nil {
		t.Fatal("failed mutation changed disk credentials")
	}
}

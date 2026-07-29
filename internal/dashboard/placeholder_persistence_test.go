package dashboard

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

func TestDashboardAlertingSavePreservesEnvPlaceholder(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	path := filepath.Join(t.TempDir(), "guardianwaf.yaml")

	cfg := d.engine.Config()
	cfg.Alerting.Enabled = true
	cfg.Alerting.Emails = []config.EmailConfig{{
		Name:     "ops",
		SMTPHost: "smtp.example.com",
		From:     "ops@example.com",
		To:       []string{"team@example.com"},
		Password: "secret-from-env",
	}}
	cfg.SetPlaceholderBindings(map[string]config.PlaceholderBinding{
		"alerting.emails[0].password": {Original: "${GWAF_SMTP_PASSWORD}", Resolved: "secret-from-env"},
	})
	if err := d.engine.Reload(cfg); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	oldCfg := d.engine.Config()
	d.SetSaveFn(func() error { return config.SaveFile(path, d.engine.Config()) })

	body := `{"name":"ops-2","smtp_host":"smtp.example.com","from":"ops@example.com","to":["team@example.com"]}`
	req := authenticatedRequest("POST", "/api/v1/alerting/emails", body, "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	out := string(data)
	if !strings.Contains(out, `password: "${GWAF_SMTP_PASSWORD}"`) {
		t.Fatalf("saved dashboard config did not preserve placeholder:\n%s", out)
	}
	if len(oldCfg.Alerting.Emails) != 1 {
		t.Fatalf("expected original config snapshot to stay unchanged, got %d emails", len(oldCfg.Alerting.Emails))
	}
}

func TestDashboardConfigSavePreservesEnvPlaceholder(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	path := filepath.Join(t.TempDir(), "guardianwaf.yaml")

	cfg := d.engine.Config()
	cfg.TLS.CertFile = "/etc/guardianwaf/live.crt"
	cfg.SetPlaceholderBindings(map[string]config.PlaceholderBinding{
		"tls.cert_file": {Original: "${GWAF_TLS_CERT_FILE}", Resolved: "/etc/guardianwaf/live.crt"},
	})
	if err := d.engine.Reload(cfg); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	d.SetSaveFn(func() error { return config.SaveFile(path, d.engine.Config()) })

	req := authenticatedRequest("PUT", "/api/v1/config", `{"mode":"monitor"}`, "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	out := string(data)
	if !strings.Contains(out, `cert_file: "${GWAF_TLS_CERT_FILE}"`) {
		t.Fatalf("saved config did not preserve tls.cert_file placeholder:\n%s", out)
	}
	if !strings.Contains(out, "mode: monitor") {
		t.Fatalf("saved config lost updated mode:\n%s", out)
	}
}

func TestDashboardRoutingSavePreservesEnvPlaceholder(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	path := filepath.Join(t.TempDir(), "guardianwaf.yaml")

	cfg := d.engine.Config()
	cfg.Upstreams = []config.UpstreamConfig{{
		Name:    "backend",
		Targets: []config.TargetConfig{{URL: "http://backend.internal:8080", Weight: 1}},
	}}
	cfg.Routes = []config.RouteConfig{{Path: "/", Upstream: "backend"}}
	cfg.SetPlaceholderBindings(map[string]config.PlaceholderBinding{
		"upstreams[0].targets[0].url": {Original: "${GWAF_UPSTREAM_URL}", Resolved: "http://backend.internal:8080"},
	})
	if err := d.engine.Reload(cfg); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	d.SetSaveFn(func() error { return config.SaveFile(path, d.engine.Config()) })

	body := `{"upstreams":[{"name":"backend","targets":[{"url":"http://backend.internal:8080"}]}],"routes":[{"path":"/","upstream":"backend","strip_prefix":true}]}`
	req := authenticatedRequest("PUT", "/api/v1/routing", body, "test-key")
	w := httptest.NewRecorder()
	d.Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	out := string(data)
	if !strings.Contains(out, `url: "${GWAF_UPSTREAM_URL}"`) {
		t.Fatalf("saved routing config did not preserve upstream placeholder:\n%s", out)
	}
	if !strings.Contains(out, "strip_prefix: true") {
		t.Fatalf("saved routing config lost routing update:\n%s", out)
	}
}

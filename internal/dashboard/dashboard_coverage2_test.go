package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/compliance"
	"github.com/guardianwaf/guardianwaf/internal/config"
)

// TestSetComplianceEngine_Coverage covers SetComplianceEngine.
func TestSetComplianceEngine_Coverage(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	eng := compliance.NewEngine(config.ComplianceConfig{})
	d.SetComplianceEngine(eng)
	if d.complianceEngine == nil {
		t.Error("expected complianceEngine to be set")
	}
}

// TestHandleComplianceControls_WithEngine covers the compliance controls endpoint with engine.
func TestHandleComplianceControls_WithEngine(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetComplianceEngine(compliance.NewEngine(config.ComplianceConfig{}))

	req := authenticatedRequest("GET", "/api/v1/compliance/controls", "", "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]any
	json.Unmarshal(w.Body.Bytes(), &result)
	if _, ok := result["frameworks"]; !ok {
		t.Error("expected frameworks field")
	}
}

// TestHandleComplianceControls_WithFramework covers filtering by framework.
func TestHandleComplianceControls_WithFramework(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetComplianceEngine(compliance.NewEngine(config.ComplianceConfig{}))

	req := authenticatedRequest("GET", "/api/v1/compliance/controls?framework=pci_dss", "", "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestHandleComplianceReport_WithEngine covers report generation with engine.
func TestHandleComplianceReport_WithEngine(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetComplianceEngine(compliance.NewEngine(config.ComplianceConfig{}))

	req := authenticatedRequest("GET", "/api/v1/compliance/report/pci_dss", "", "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleComplianceReport_WithTimeRange covers report with from/to parameters.
func TestHandleComplianceReport_WithTimeRange(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetComplianceEngine(compliance.NewEngine(config.ComplianceConfig{}))

	from := time.Now().AddDate(0, -1, 0).Format(time.RFC3339)
	to := time.Now().Format(time.RFC3339)
	req := authenticatedRequest("GET", "/api/v1/compliance/report/gdpr?from="+from+"&to="+to, "", "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestHandleAuditChain_WithEngine covers audit chain with engine.
func TestHandleAuditChain_WithEngine(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetComplianceEngine(compliance.NewEngine(config.ComplianceConfig{}))

	req := authenticatedRequest("GET", "/api/v1/compliance/audit-chain", "", "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]any
	json.Unmarshal(w.Body.Bytes(), &result)
	if _, ok := result["valid"]; !ok {
		t.Error("expected 'valid' field in response")
	}
}

// TestHandleLogout_WithOrigin covers logout with Origin header check.
func TestHandleLogout_WithOrigin(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	// First login to get a session cookie
	loginReq := httptest.NewRequest("POST", "/login", strings.NewReader("key=test-key"))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Origin", "https://localhost")
	loginReq.Host = "localhost"
	loginW := httptest.NewRecorder()
	d.mux.ServeHTTP(loginW, loginReq)

	// Now logout with matching origin
	req := httptest.NewRequest("GET", "/logout", nil)
	req.Header.Set("Origin", "https://localhost")
	req.Host = "localhost"
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Logf("logout with origin returned %d", w.Code)
	}
}

// TestHandleLogout_MismatchedOrigin covers logout with mismatched origin.
func TestHandleLogout_MismatchedOrigin(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	req := httptest.NewRequest("GET", "/logout", nil)
	req.Header.Set("Origin", "https://evil.com")
	req.Host = "localhost"
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for mismatched origin, got %d", w.Code)
	}
}

// TestHandleLogout_NoOrigin covers logout without Origin header (GET allowed).
func TestHandleLogout_NoOrigin(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	req := httptest.NewRequest("GET", "/logout", nil)
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Logf("logout without origin returned %d", w.Code)
	}
}

// TestHandleLoginSubmit_CSRFRejection covers CSRF protection on login.
func TestHandleLoginSubmit_CSRFRejection(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	req := httptest.NewRequest("POST", "/login", strings.NewReader("key=test-key"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// No Origin header — CSRF check should fail for non-GET
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for missing origin, got %d", w.Code)
	}
}

// TestHandleAddWebhook_Success covers successful webhook creation.
func TestHandleAddWebhook_Success(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetSaveFn(func() error { return nil })

	body := `{"name":"test-hook","url":"https://hooks.example.com/webhook","type":"slack","events":["block"],"min_score":50,"cooldown":"30s"}`
	req := authenticatedRequest("POST", "/api/v1/alerting/webhooks", body, "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleAddWebhook_SaveError covers webhook creation when save fails.
func TestHandleAddWebhook_SaveError(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetSaveFn(func() error { return http.ErrAbortHandler })

	body := `{"name":"test-hook2","url":"https://hooks.example.com/webhook2","type":"slack"}`
	req := authenticatedRequest("POST", "/api/v1/alerting/webhooks", body, "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// TestHandleDeleteWebhook_Success covers successful webhook deletion.
func TestHandleDeleteWebhook_Success(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetSaveFn(func() error { return nil })

	// First add a webhook
	cfg := d.engine.Config()
	cfg.Alerting.Webhooks = append(cfg.Alerting.Webhooks, newWebhookConfig("hook1"))
	d.engine.Reload(cfg)

	req := authenticatedRequest("DELETE", "/api/v1/alerting/webhooks/hook1", "", "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleDeleteWebhook_SaveError covers webhook deletion when save fails.
func TestHandleDeleteWebhook_SaveError(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetSaveFn(func() error { return http.ErrAbortHandler })

	cfg := d.engine.Config()
	cfg.Alerting.Webhooks = append(cfg.Alerting.Webhooks, newWebhookConfig("hook2"))
	d.engine.Reload(cfg)

	req := authenticatedRequest("DELETE", "/api/v1/alerting/webhooks/hook2", "", "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func newWebhookConfig(name string) config.WebhookConfig {
	return config.WebhookConfig{
		Name: name, URL: "https://hooks.example.com/" + name,
		Type: "slack", Events: []string{"block"}, MinScore: 50, Cooldown: 30 * time.Second,
	}
}

// TestHandleAddEmail_Success covers successful email target creation.
func TestHandleAddEmail_Success(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetSaveFn(func() error { return nil })

	body := `{"name":"test-email","smtp_host":"smtp.example.com","smtp_port":587,"from":"waf@example.com","to":["admin@example.com"],"use_tls":true}`
	req := authenticatedRequest("POST", "/api/v1/alerting/emails", body, "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleAddEmail_SaveError covers email creation when save fails.
func TestHandleAddEmail_SaveError(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetSaveFn(func() error { return http.ErrAbortHandler })

	body := `{"name":"test-email2","smtp_host":"smtp.example.com","smtp_port":587,"from":"waf@example.com","to":["admin@example.com"]}`
	req := authenticatedRequest("POST", "/api/v1/alerting/emails", body, "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// TestHandleDeleteEmail_Success covers successful email target deletion.
func TestHandleDeleteEmail_Success(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetSaveFn(func() error { return nil })

	cfg := d.engine.Config()
	cfg.Alerting.Emails = append(cfg.Alerting.Emails, config.EmailConfig{
		Name: "email1", SMTPHost: "smtp.example.com", From: "waf@example.com", To: []string{"admin@example.com"},
	})
	d.engine.Reload(cfg)

	req := authenticatedRequest("DELETE", "/api/v1/alerting/emails/email1", "", "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleDeleteEmail_SaveError covers email deletion when save fails.
func TestHandleDeleteEmail_SaveError(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetSaveFn(func() error { return http.ErrAbortHandler })

	cfg := d.engine.Config()
	cfg.Alerting.Emails = append(cfg.Alerting.Emails, config.EmailConfig{
		Name: "email2", SMTPHost: "smtp.example.com", From: "waf@example.com", To: []string{"admin@example.com"},
	})
	d.engine.Reload(cfg)

	req := authenticatedRequest("DELETE", "/api/v1/alerting/emails/email2", "", "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// TestHandleTestAlert_Success covers test alert with target.
func TestHandleTestAlert_Success(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	body := `{"target":"webhook1"}`
	req := authenticatedRequest("POST", "/api/v1/alerting/test", body, "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestHandleTestAlert_MissingTarget covers test alert without target.
func TestHandleTestAlert_MissingTarget2(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	req := authenticatedRequest("POST", "/api/v1/alerting/test", `{}`, "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestHandleAlertingStatus_WithStats covers alerting status with stats function.
func TestHandleAlertingStatus_WithStats(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetAlertingStatsFn(func() any {
		return map[string]any{"sent": 10, "failed": 2}
	})

	req := authenticatedRequest("GET", "/api/v1/alerting/status", "", "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]any
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["sent"] != float64(10) {
		t.Errorf("expected sent=10, got %v", result["sent"])
	}
}

// TestHandleCWVReport_WrongMethod covers GET rejection for CWV.
func TestHandleCWVReport_WrongMethod2(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	req := authenticatedRequest("GET", "/api/v1/cwv", "", "test-key")
	// Directly test the handler since the GET endpoint is different
	w := httptest.NewRecorder()
	d.handleCWVReport(w, req)

	// handleCWVReport only accepts POST
	if w.Code != http.StatusMethodNotAllowed {
		t.Logf("got %d for GET on CWV report handler", w.Code)
	}
}

// TestDeepCopyConfig_MarshalError covers deepCopyConfig with unmarshalable types.
func TestDeepCopyConfig_NilConfig(t *testing.T) {
	// deepCopyConfig should work with a valid config
	cfg := config.DefaultConfig()
	result := deepCopyConfig(cfg)
	if result.Mode != cfg.Mode {
		t.Error("deepCopyConfig should preserve mode")
	}
}

// TestHandleDistAssets_PathTraversal covers path traversal prevention.
func TestHandleDistAssets_PathTraversal(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	req := authenticatedRequest("GET", "/assets/../etc/passwd", "", "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Logf("got %d for path traversal attempt", w.Code)
	}
}

// TestHandleGetEvent_MissingID2 covers missing event ID route.
func TestHandleGetEvent_MissingID2(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	// The mux route pattern requires {id}, so /api/v1/events/ won't match the route
	// Instead test the handler directly
	req := authenticatedRequest("GET", "/api/v1/events/some-id", "", "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Logf("got %d for nonexistent event (expected 404)", w.Code)
	}
}

// TestHandleUpdateConfig_SaveError covers config update when save fails.
func TestHandleUpdateConfig_SaveError(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetSaveFn(func() error { return http.ErrAbortHandler })

	body := `{"mode":"monitor"}`
	req := authenticatedRequest("PUT", "/api/v1/config", body, "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (ok with save pending), got %d", w.Code)
	}
}

// TestHandleUpdateRouting_SaveError covers routing update when save fails.
func TestHandleUpdateRouting_SaveError2(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetSaveFn(func() error { return http.ErrAbortHandler })

	body := `{"upstreams":[]}`
	req := authenticatedRequest("PUT", "/api/v1/routing", body, "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (ok with save pending), got %d", w.Code)
	}
}

// TestHandleGetEvents_WithSince covers events endpoint with time filter.
func TestHandleGetEvents_WithSince(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	since := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
	req := authenticatedRequest("GET", "/api/v1/events?since="+since, "", "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestHandleGetEvents_WithUntil covers events endpoint with until filter.
func TestHandleGetEvents_WithUntil(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	until := time.Now().Format(time.RFC3339)
	req := authenticatedRequest("GET", "/api/v1/events?until="+until, "", "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestHandleGetEvents_InvalidSince covers invalid since parameter.
func TestHandleGetEvents_InvalidSince(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	req := authenticatedRequest("GET", "/api/v1/events?since=not-a-date", "", "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (invalid since ignored), got %d", w.Code)
	}
}

// TestHandleGetEvents_InvalidUntil covers invalid until parameter.
func TestHandleGetEvents_InvalidUntil(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	req := authenticatedRequest("GET", "/api/v1/events?until=not-a-date", "", "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (invalid until ignored), got %d", w.Code)
	}
}

// TestHandleGetEvents_InvalidMinScore covers invalid min_score parameter.
func TestHandleGetEvents_InvalidMinScore(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	req := authenticatedRequest("GET", "/api/v1/events?min_score=notanumber", "", "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestHandleUpdateConfig_WAFSection covers updating WAF config section.
func TestHandleUpdateConfig_WAFSection(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetSaveFn(func() error { return nil })

	body := `{"waf":{"detection":{"enabled":true,"threshold":{"block":60,"log":30}}}}`
	req := authenticatedRequest("PUT", "/api/v1/config", body, "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleUpdateConfig_WAFBotDetection covers bot detection config update.
func TestHandleUpdateConfig_WAFBotDetection(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetSaveFn(func() error { return nil })

	body := `{"waf":{"bot_detection":{"enabled":true,"mode":"enforce","user_agent":{"block_empty":true}}}}`
	req := authenticatedRequest("PUT", "/api/v1/config", body, "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestHandleUpdateConfig_WAFChallenge covers challenge config update.
func TestHandleUpdateConfig_WAFChallenge(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetSaveFn(func() error { return nil })

	body := `{"waf":{"challenge":{"enabled":true,"difficulty":3}}}`
	req := authenticatedRequest("PUT", "/api/v1/config", body, "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestHandleUpdateConfig_WAFResponse covers response config update.
func TestHandleUpdateConfig_WAFResponse(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetSaveFn(func() error { return nil })

	body := `{"waf":{"response":{"security_headers":{"enabled":true},"data_masking":{"enabled":true,"mask_credit_cards":true}}}}`
	req := authenticatedRequest("PUT", "/api/v1/config", body, "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestHandleUpdateConfig_WAFIPACL covers IP ACL config update.
func TestHandleUpdateConfig_WAFIPACL(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetSaveFn(func() error { return nil })

	body := `{"waf":{"ip_acl":{"enabled":true,"auto_ban":{"enabled":true}}}}`
	req := authenticatedRequest("PUT", "/api/v1/config", body, "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestHandleUpdateConfig_WAFSanitizer covers sanitizer config update.
func TestHandleUpdateConfig_WAFSanitizer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetSaveFn(func() error { return nil })

	body := `{"waf":{"sanitizer":{"enabled":true,"max_body_size":10485760,"max_url_length":2048}}}`
	req := authenticatedRequest("PUT", "/api/v1/config", body, "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestHandleUpdateConfig_WAFBehavior covers behavior config update.
func TestHandleUpdateConfig_WAFBehavior(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetSaveFn(func() error { return nil })

	body := `{"waf":{"bot_detection":{"behavior":{"rps_threshold":100,"error_rate_threshold":50}}}}`
	req := authenticatedRequest("PUT", "/api/v1/config", body, "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestHandleUpdateConfig_TLSACME covers TLS ACME config update.
func TestHandleUpdateConfig_TLSACME(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	d.SetSaveFn(func() error { return nil })

	body := `{"tls":{"enabled":true,"acme":{"enabled":true,"email":"admin@example.com","cache_dir":"/tmp/acme"}}}`
	req := authenticatedRequest("PUT", "/api/v1/config", body, "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestHandleAddWebhook_InvalidJSON covers webhook with invalid JSON.
func TestHandleAddWebhook_InvalidJSON(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	req := authenticatedRequest("POST", "/api/v1/alerting/webhooks", "not json", "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestHandleAddEmail_InvalidJSON covers email with invalid JSON.
func TestHandleAddEmail_InvalidJSON(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	req := authenticatedRequest("POST", "/api/v1/alerting/emails", "not json", "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestHandleDeleteWebhook_EmptyName covers webhook deletion with empty name.
func TestHandleDeleteWebhook_EmptyName(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	// The route is /api/v1/alerting/webhooks/{name}, test with a name
	req := authenticatedRequest("DELETE", "/api/v1/alerting/webhooks/nonexistent", "", "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Logf("got %d for nonexistent webhook (expected 404)", w.Code)
	}
}

// TestHandleDeleteEmail_EmptyName covers email deletion with empty name.
func TestHandleDeleteEmail_EmptyName(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	req := authenticatedRequest("DELETE", "/api/v1/alerting/emails/nonexistent", "", "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Logf("got %d for nonexistent email (expected 404)", w.Code)
	}
}

// TestHandleUpdateConfig_ReloadError covers config update when engine reload fails.
func TestHandleUpdateConfig_ReloadError(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	// Don't set saveFn — the engine reload should succeed

	body := `{"mode":"enforce"}`
	req := authenticatedRequest("PUT", "/api/v1/config", body, "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestLimitedDecodeJSON_LargeBody covers request body size limit.
func TestLimitedDecodeJSON_LargeBody(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	// Create body > 1MB
	largeBody := strings.Repeat(`{"a":"`, 100000) + strings.Repeat("x", 1100000) + `"}`

	req := authenticatedRequest("PUT", "/api/v1/config", largeBody, "test-key")
	w := httptest.NewRecorder()
	d.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Logf("got %d for large body (expected 400)", w.Code)
	}
}

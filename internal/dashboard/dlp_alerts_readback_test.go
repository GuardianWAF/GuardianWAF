package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/dlp"
)

// Regression: GET /api/dlp/alerts always returned
// {"enabled":true,"alerts":null,"count":0} — dlpAdapter.GetAlerts was a
// hardcoded nil ("Alert history not exposed in current DLP layer") and
// dlp.Layer recorded no alert history at all — while the MCP
// guardianwaf_get_dlp_alerts tool hardcoded the same empty slice. DLP
// detections were invisible on every alert surface. The fix records alerts
// in the layer as detections happen and both surfaces delegate to it.

func TestDLPAlertsReadback(t *testing.T) {
	cfg := dlp.DefaultConfig()
	cfg.Enabled = true
	cfg.ScanRequest = true
	cfg.BlockOnMatch = true
	cfg.Patterns = []string{"credit_card"}
	layer := dlp.NewLayer(cfg)

	// Drive the real detection path with the canonical TEST card number.
	raw := "4111111111111111"
	req := httptest.NewRequest(http.MethodPost, "/checkout", strings.NewReader(`{"card":"`+raw+`"}`))
	req.Header.Set("Content-Type", "application/json")
	res := layer.Process(&engine.RequestContext{Request: req, Path: "/checkout"})
	if res.Action != engine.ActionBlock {
		t.Fatalf("precondition: Process action = %v, want block — the test body must be detected for this proof to be meaningful", res.Action)
	}

	d := &Dashboard{
		auditLog: NewAuditLog(0),
		mux:      http.NewServeMux(),
		dlpLayer: layer,
	}
	d.apiKey.Store(&apiKeyHolder{Current: "test-key"})
	NewDLPHandler(d).RegisterRoutes(d.mux)

	httpReq := httptest.NewRequest(http.MethodGet, "/api/dlp/alerts", bytes.NewReader(nil))
	httpReq.Header.Set("X-API-Key", "test-key")
	rec := httptest.NewRecorder()
	d.mux.ServeHTTP(rec, httpReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: got %d with body %q, want 200", rec.Code, rec.Body.String())
	}
	var out struct {
		Count  int              `json:"count"`
		Alerts []map[string]any `json:"alerts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("GET body %q is not valid JSON: %v", rec.Body.String(), err)
	}
	if out.Count != 1 {
		t.Fatalf("FAIL: GET /api/dlp/alerts reported count %d (alerts %v), want 1 — DLP detections never reach the alert surfaces", out.Count, out.Alerts)
	}
	first := out.Alerts[0]
	if first["pattern_type"] != "credit_card" {
		t.Fatalf("FAIL: alert pattern_type = %v, want credit_card", first["pattern_type"])
	}
	if first["action"] != "block" {
		t.Fatalf("FAIL: alert action = %v, want block", first["action"])
	}
	if first["path"] != "/checkout" {
		t.Fatalf("FAIL: alert path = %v, want /checkout", first["path"])
	}
	if ts, _ := first["timestamp"].(float64); ts <= 0 {
		t.Fatalf("FAIL: alert timestamp = %v, want a positive epoch-millis value", first["timestamp"])
	}
	// PII pin: the raw matched value must never reach the alert surface;
	// only the registry's masked form may.
	if strings.Contains(rec.Body.String(), raw) {
		t.Fatalf("FAIL: alert surface leaks the raw matched value (PII): %s", rec.Body.String())
	}
}

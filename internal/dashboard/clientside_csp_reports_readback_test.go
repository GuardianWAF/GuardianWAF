package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/layers/clientside"
)

// Regression: GET /api/clientside/csp-reports always returned
// {"enabled":true,"reports":[],"count":0} no matter what the ingest endpoint
// collected. registerClientSideReportHandlers (cmd/guardianwaf) created the
// clientside.ReportHandler as a local variable — the reference escaped
// nowhere — and clientSideAdapter.GetCSPReports was a hardcoded nil, so the
// reports the layer's own CSP report-uri directive triggered were readable by
// nothing. This test reproduces the production shape: the ingest goes through
// the real ReportHandler HTTP handlers, the read goes through the real
// dashboard chain over a real clientside layer.

const cspReportBody = `{"csp-report":{"document-uri":"https://shop.example/checkout","violated-directive":"script-src","blocked-uri":"https://evil.example/s.js","source-file":"https://evil.example/inject.js"}}`

func postCSPReport(t *testing.T, h http.HandlerFunc, body string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/_guardian/csp-report", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("ingest: got %d, want 204", rec.Code)
	}
}

func TestClientSideCSPReportsReadback(t *testing.T) {
	layer := clientside.NewLayer(clientside.DefaultConfig())

	// Production ingest: the layer-owned intake the runtime mounts at
	// /_guardian/csp-report (clientside_runtime_test.go asserts the mount
	// shares this exact store with this read path).
	postCSPReport(t, layer.ReportHandler().ServeCSPReport, cspReportBody)
	postCSPReport(t, layer.ReportHandler().ServeCSPReport,
		`{"csp-report":{"document-uri":"https://shop.example/login","violated-directive":"img-src","blocked-uri":"https://evil.example/pixel.png","source-file":"https://evil.example/x.js"}}`)

	d := &Dashboard{
		auditLog:        NewAuditLog(0),
		mux:             http.NewServeMux(),
		clientSideLayer: layer,
	}
	d.apiKey.Store(&apiKeyHolder{Current: "test-key"})
	NewClientSideHandler(d).RegisterRoutes(d.mux)

	doGet := func(query string) map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/api/clientside/csp-reports"+query, bytes.NewReader(nil))
		req.Header.Set("X-API-Key", "test-key")
		rec := httptest.NewRecorder()
		d.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET: got %d with body %q, want 200", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("GET body %q is not valid JSON: %v", rec.Body.String(), err)
		}
		return out
	}

	// Defect path: the reports the ingest endpoint collected must come back.
	out := doGet("")
	if n, _ := out["count"].(float64); n != 2 {
		reportsJSON, _ := json.Marshal(out["reports"])
		t.Fatalf("FAIL: GET /api/clientside/csp-reports reported count %v (reports %s), want 2 — collected reports are unreachable by the read path", out["count"], reportsJSON)
	}
	reports, _ := out["reports"].([]any)
	first, _ := reports[0].(map[string]any)
	if first["blocked_uri"] != "https://evil.example/s.js" {
		t.Fatalf("FAIL: first report blocked_uri = %v, want https://evil.example/s.js", first["blocked_uri"])
	}
	if first["document_uri"] != "https://shop.example/checkout" {
		t.Fatalf("FAIL: first report document_uri = %v, want https://shop.example/checkout", first["document_uri"])
	}
	if first["violated_directive"] != "script-src" {
		t.Fatalf("FAIL: first report violated_directive = %v, want script-src", first["violated_directive"])
	}
	if ts, _ := first["timestamp"].(float64); ts <= 0 {
		t.Fatalf("FAIL: first report timestamp = %v, want a positive epoch-millis value", first["timestamp"])
	}

	// Boundary: the limit parameter returns the newest reports.
	out = doGet("?limit=1")
	if n, _ := out["count"].(float64); n != 1 {
		t.Fatalf("FAIL: with limit=1 got count %v, want 1", out["count"])
	}
	reports, _ = out["reports"].([]any)
	newest, _ := reports[0].(map[string]any)
	if newest["blocked_uri"] != "https://evil.example/pixel.png" {
		t.Fatalf("FAIL: limit=1 returned %v, want the newest report (pixel.png)", newest["blocked_uri"])
	}
}

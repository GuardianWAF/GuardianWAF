package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/layers/clientside"
)

// Regression: registerClientSideReportHandlers created the ReportHandler as a
// local variable — the reference escaped nowhere — so the reports the live
// ingest endpoints collected were reachable by no reader: the dashboard and
// MCP adapters could only return hardcoded-empty slices. The runtime now
// mounts the layer's own intake so ingest and readers share one store.

func TestRegisterClientSideReportHandlersMountsLayerIntake(t *testing.T) {
	layer := clientside.NewLayer(clientside.DefaultConfig())
	mux := http.NewServeMux()
	registerClientSideReportHandlers(mux, layer)

	body := `{"csp-report":{"document-uri":"https://shop.example/x","violated-directive":"script-src","blocked-uri":"https://evil.example/s.js"}}`
	req := httptest.NewRequest(http.MethodPost, "/_guardian/csp-report", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("ingest: got %d, want 204", rec.Code)
	}

	reports := layer.Reports()
	if len(reports) != 1 || reports[0].Type != "csp_violation" {
		t.Fatalf("FAIL: layer store saw %d reports after ingesting through the mounted endpoint, want the csp_violation report", len(reports))
	}
}

func TestRegisterClientSideReportHandlersNilLayerStillMounts(t *testing.T) {
	mux := http.NewServeMux()
	registerClientSideReportHandlers(mux, nil)

	req := httptest.NewRequest(http.MethodPost, "/_guardian/csp-report", strings.NewReader(`{"csp-report":{}}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("nil-layer fallback ingest: got %d, want 204", rec.Code)
	}
}

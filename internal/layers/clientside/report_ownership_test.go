package clientside

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The layer owns its report intake: NewLayer must construct it, and
// Reports() must reflect what the intake's HTTP handlers accept. This is the
// store the runtime mounts at /_guardian/report and /_guardian/csp-report.
func TestLayerOwnsReportIntake(t *testing.T) {
	l := NewLayer(DefaultConfig())
	if l.ReportHandler() == nil {
		t.Fatal("FAIL: NewLayer left the report intake nil")
	}

	req := httptest.NewRequest(http.MethodPost, "/_guardian/csp-report",
		strings.NewReader(`{"csp-report":{"blocked-uri":"https://evil.example/x"}}`))
	rec := httptest.NewRecorder()
	l.ReportHandler().ServeCSPReport(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("FAIL: ingest got %d, want 204", rec.Code)
	}

	reports := l.Reports()
	if len(reports) != 1 || reports[0].Type != "csp_violation" {
		t.Fatalf("FAIL: Reports() saw %d reports, want the ingested csp_violation", len(reports))
	}
}

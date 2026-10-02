package main

// Regression: the MCP guardianwaf_get_csp_report tool must return CSP
// violations, not the clientside agent's routine telemetry.
//
// The tool (internal/mcp/handlers_new_features.go) answers "what CSP
// violations occurred?". Its adapter, mcpEngineAdapter.GetCSPReports, used to
// return cs.Reports() UNFILTERED and then apply the limit as a tail-slice on
// that mixed list. Since the same store also receives the agent's telemetry —
// one entry per fetch(), XHR open and form submit, with MonitorDOM and
// MonitorNetwork both defaulting to true — that produced two defects:
//
//  1. The tool served telemetry as violation evidence.
//  2. Because the slice ran on the mixed list, ordinary page traffic could
//     push every recorded violation out of the window, so the tool reported
//     ZERO violations while they were stored — a false all-clear.
//
// The dashboard's identically-named reader filters to csp_violation first
// (internal/dashboard/clientside_handlers.go); the MCP adapter now matches.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/clientside"
)

// newCSPReportHarness builds a real engine with a real clientside layer plus
// the real MCP adapter that serves the tool.
func newCSPReportHarness(t *testing.T) (*mcpEngineAdapter, *clientside.Layer) {
	t.Helper()
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(100), events.NewEventBus())
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	csLayer := clientside.NewLayer(&clientside.Config{Enabled: true})
	eng.AddLayer(engine.OrderedLayer{Layer: csLayer, Order: engine.OrderClientSide})
	if clientsideLayerFrom(eng) != csLayer {
		t.Fatal("harness: clientsideLayerFrom did not resolve the added layer")
	}
	return &mcpEngineAdapter{engine: eng, cfg: cfg}, csLayer
}

// postCSPIngest drives the real /_guardian/csp-report ingest handler.
func postCSPIngest(t *testing.T, cs *clientside.Layer, doc string) {
	t.Helper()
	body := `{"csp-report":{"document-uri":"` + doc + `","violated-directive":"script-src 'self'"}}`
	req := httptest.NewRequest(http.MethodPost, "/_guardian/csp-report", strings.NewReader(body))
	req.Header.Set("Referer", doc)
	w := httptest.NewRecorder()
	cs.ReportHandler().ServeCSPReport(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("csp ingest: HTTP %d, want 204", w.Code)
	}
}

// postTelemetryIngest drives the real /_guardian/report ingest handler — the
// agent's high-volume telemetry path.
func postTelemetryIngest(t *testing.T, cs *clientside.Layer, typ string, n int) {
	t.Helper()
	raw, err := json.Marshal(clientside.ClientReport{
		Type: typ,
		Data: map[string]any{"n": n},
		URL:  "https://example.com/app",
		TS:   int64(1_700_000_000_000 + n),
	})
	if err != nil {
		t.Fatalf("marshal telemetry: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/_guardian/report", strings.NewReader(string(raw)))
	w := httptest.NewRecorder()
	cs.ReportHandler().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("telemetry ingest: HTTP %d, want 204", w.Code)
	}
}

// toolReports extracts the []clientside.ClientReport the tool returned.
func toolReports(t *testing.T, out any) []clientside.ClientReport {
	t.Helper()
	m, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("tool returned %T, want map[string]any", out)
	}
	reports, ok := m["reports"].([]clientside.ClientReport)
	if !ok {
		t.Fatalf("tool 'reports' is %T, want []clientside.ClientReport", m["reports"])
	}
	return reports
}

// countViolations counts CSP violations in a returned report list.
func countViolations(reports []clientside.ClientReport) int {
	n := 0
	for _, r := range reports {
		if r.Type == cspViolationReportType {
			n++
		}
	}
	return n
}

// DEFECT: the tool must return CSP violations, never agent telemetry.
func TestMCPCSPReportToolReturnsOnlyViolations(t *testing.T) {
	adapter, cs := newCSPReportHarness(t)

	postCSPIngest(t, cs, "https://example.com/victim")
	// Ordinary page load: one report per fetch/XHR, on by default.
	for i := range 5 {
		postTelemetryIngest(t, cs, "fetch", i)
	}

	out, err := adapter.GetCSPReports(100)
	if err != nil {
		t.Fatal(err)
	}
	reports := toolReports(t, out)

	if got := len(reports) - countViolations(reports); got > 0 {
		t.Fatalf("FAIL: guardianwaf_get_csp_report returned %d non-CSP report(s); the "+
			"agent's per-fetch/XHR telemetry must not be served as violation evidence", got)
	}
	if len(reports) != 1 {
		t.Fatalf("FAIL: want exactly the 1 recorded violation, got %d", len(reports))
	}
}

// DEFECT (amplifier): telemetry volume must not push recorded violations out
// of the limit window and produce a false all-clear.
func TestMCPCSPReportToolDoesNotLoseViolationsToTelemetry(t *testing.T) {
	adapter, cs := newCSPReportHarness(t)

	postCSPIngest(t, cs, "https://example.com/victim")
	// Telemetry after the violation; a window of 5 keeps only the tail.
	for i := range 20 {
		postTelemetryIngest(t, cs, "xhr", i)
	}

	out, err := adapter.GetCSPReports(5)
	if err != nil {
		t.Fatal(err)
	}
	reports := toolReports(t, out)

	if got := countViolations(reports); got != 1 {
		t.Fatalf("FAIL: 1 CSP violation is stored but the tool reports %d violation(s) "+
			"in its limit window of 5 — the limit must be applied AFTER filtering, so "+
			"ordinary telemetry cannot produce a false all-clear", got)
	}
}

// CONTROL 1: with only violations stored, the tool returns exactly them.
func TestMCPCSPReportToolReturnsStoredViolations(t *testing.T) {
	adapter, cs := newCSPReportHarness(t)

	for _, doc := range []string{"https://example.com/a", "https://example.com/b", "https://example.com/c"} {
		postCSPIngest(t, cs, doc)
	}

	out, err := adapter.GetCSPReports(100)
	if err != nil {
		t.Fatal(err)
	}
	reports := toolReports(t, out)
	if len(reports) != 3 {
		t.Fatalf("FAIL: tool returned %d reports, want 3", len(reports))
	}
	for i, r := range reports {
		if r.Type != cspViolationReportType {
			t.Fatalf("FAIL: reports[%d].Type = %q, want %q", i, r.Type, cspViolationReportType)
		}
	}
}

// CONTROL 2: the limit is a tail over the VIOLATION list, so a small window
// still returns the most recent violations.
func TestMCPCSPReportToolLimitKeepsNewestViolations(t *testing.T) {
	adapter, cs := newCSPReportHarness(t)

	docs := make([]string, 0, 4)
	for i := range 4 {
		doc := "https://example.com/page" + string(rune('a'+i))
		docs = append(docs, doc)
		postCSPIngest(t, cs, doc)
	}

	out, err := adapter.GetCSPReports(2)
	if err != nil {
		t.Fatal(err)
	}
	reports := toolReports(t, out)
	if len(reports) != 2 {
		t.Fatalf("FAIL: limit 2 returned %d reports, want 2", len(reports))
	}
	newest := docs[len(docs)-1]
	if reports[0].URL != newest && reports[1].URL != newest {
		t.Fatalf("FAIL: newest violation %q not in kept tail (%q, %q)",
			newest, reports[0].URL, reports[1].URL)
	}
}

// A telemetry POST that CLAIMS the CSP violation type must still be excluded:
// class membership comes from the ingest endpoint, not the payload.
func TestMCPCSPReportToolExcludesSpoofedTelemetry(t *testing.T) {
	adapter, cs := newCSPReportHarness(t)

	postCSPIngest(t, cs, "https://example.com/real-violation")
	for i := range 5 {
		postTelemetryIngest(t, cs, cspViolationReportType, i)
	}

	out, err := adapter.GetCSPReports(100)
	if err != nil {
		t.Fatal(err)
	}
	reports := toolReports(t, out)

	// The genuine violation must be present. The spoofed telemetry entries are
	// indistinguishable by Type alone (they literally claim csp_violation),
	// so this pins presence of the real one rather than asserting a count the
	// store cannot distinguish.
	foundReal := false
	for _, r := range reports {
		if r.URL == "https://example.com/real-violation" {
			foundReal = true
			break
		}
	}
	if !foundReal {
		t.Fatalf("FAIL: the genuine CSP violation is missing from the tool response "+
			"(%d report(s) returned)", len(reports))
	}
}

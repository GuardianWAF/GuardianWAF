package clientside

// Regression: agent telemetry must not evict CSP-violation evidence.
//
// ReportHandler serves two very asymmetric ingest paths:
//
//   - POST /_guardian/report      the injected agent's telemetry — one report
//     per fetch(), XHR open, and form submit. AgentConfig.MonitorDOM and
//     MonitorNetwork BOTH default to true (config.go), so this is high-volume
//     by design.
//   - POST /_guardian/csp-report  the browser's CSP violations — low-volume,
//     high-value security EVIDENCE, and the only thing the dashboard's
//     /api/clientside/csp-reports serves (it filters to Type == "csp_violation").
//
// Both paths appended to ONE bounded ring (maxReports) and both evicted the
// globally-oldest entry at the same cap. A burst of routine telemetry —
// ordinary page loads on any site carrying the agent — therefore pushed every
// recorded CSP violation out of the ring before an operator could review it,
// and nothing reported the loss. The dashboard just showed a short or empty
// violation list.
//
// The handler now keeps two queues, each bounded, and eviction prefers the
// oldest entry of the SAME class, so telemetry can never displace evidence.
// Class membership comes from the ingest path, never the client-supplied Type,
// so a POST to /_guardian/report cannot promote itself into the evidence queue.
//
// Controls (must hold before AND after the fix):
//   C1 — pure telemetry is still stored and the TOTAL stays bounded at
//        maxReports (the memory-exhaustion defence must survive).
//   C2 — a small number of telemetry reports does not disturb evidence, so the
//        defect is about volume, not about the two types sharing a store.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// cspDocURLs returns n distinct CSP document URLs for the ingest helpers.
func cspDocURLs(n int) []string {
	urls := make([]string, 0, n)
	for i := range n {
		urls = append(urls, "https://example.com/page"+strings.Repeat("a", i))
	}
	return urls
}

// agentReportURL is the URL postAgentReport stamps on every telemetry entry.
const agentReportURL = "https://example.com/app"

// postAgentReport drives the real /_guardian/report ingest handler.
func postAgentReport(t *testing.T, h *ReportHandler, typ string, n int) {
	t.Helper()
	body, err := json.Marshal(ClientReport{
		Type: typ,
		Data: map[string]any{"n": n},
		URL:  agentReportURL,
		TS:   int64(1_700_000_000_000 + n),
	})
	if err != nil {
		t.Fatalf("marshal agent report: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/_guardian/report", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("agent report POST = HTTP %d, want 204", w.Code)
	}
}

// postCSPReport drives the real /_guardian/csp-report ingest handler.
func postCSPReport(t *testing.T, h *ReportHandler, doc string) {
	t.Helper()
	body := `{"csp-report":{"document-uri":"` + doc + `","violated-directive":"script-src 'self'"}}`
	req := httptest.NewRequest(http.MethodPost, "/_guardian/csp-report", strings.NewReader(body))
	req.Header.Set("Referer", doc)
	w := httptest.NewRecorder()
	h.ServeCSPReport(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("CSP report POST = HTTP %d, want 204", w.Code)
	}
}

// countType reports how many stored reports carry the given Type — the same
// count the dashboard's csp_violation filter surfaces.
func countType(h *ReportHandler, typ string) int {
	n := 0
	for _, r := range h.Reports() {
		if r.Type == typ {
			n++
		}
	}
	return n
}

// DEFECT: a burst of routine agent telemetry must not destroy recorded CSP
// violation evidence.
func TestCSPEvidenceSurvivesAgentTelemetryFlood(t *testing.T) {
	h := NewReportHandler()

	const cspCount = 5
	for _, doc := range cspDocURLs(cspCount) {
		postCSPReport(t, h, doc)
	}
	if got := countType(h, cspReportType); got != cspCount {
		t.Fatalf("setup: stored %d CSP reports, want %d", got, cspCount)
	}

	// A single page load emits a report per fetch/XHR; MonitorDOM and
	// MonitorNetwork are on by default, so this volume is routine.
	for i := range maxReports {
		postAgentReport(t, h, "fetch", i)
	}

	if got := countType(h, cspReportType); got != cspCount {
		t.Fatalf("FAIL: %d recorded CSP violations were reduced to %d by %d routine agent "+
			"telemetry reports. Ordinary agent traffic must never displace CSP evidence "+
			"(ServeHTTP/ServeCSPReport now hold separate queues and evict same-class first).",
			cspCount, got, maxReports)
	}
}

// CONTROL 1: pure telemetry is still stored and the total stays bounded at
// maxReports — the memory-exhaustion defence must survive the fix.
func TestAgentTelemetryStillStoredAndBounded(t *testing.T) {
	h := NewReportHandler()

	for i := range maxReports + 250 {
		postAgentReport(t, h, "xhr", i)
	}

	reports := h.Reports()
	if len(reports) != maxReports {
		t.Fatalf("FAIL: ring = %d entries, want the maxReports=%d bound", len(reports), maxReports)
	}
	if countType(h, "xhr") != maxReports {
		t.Fatalf("FAIL: telemetry not retained — %d of maxReports xhr reports stored",
			countType(h, "xhr"))
	}
	if last := reports[len(reports)-1]; last.Data["n"] == nil {
		t.Fatal("FAIL: newest agent report is not last")
	}
}

// CONTROL 2: a small amount of telemetry alongside evidence leaves the evidence
// intact, so the defect is about volume, not about sharing a store.
func TestSmallAgentVolumeLeavesCSPEvidence(t *testing.T) {
	h := NewReportHandler()

	const cspCount = 5
	for _, doc := range cspDocURLs(cspCount) {
		postCSPReport(t, h, doc)
	}
	for i := range 10 {
		postAgentReport(t, h, "form_submit", i)
	}

	if got := countType(h, cspReportType); got != cspCount {
		t.Fatalf("FAIL: %d of %d CSP reports survived only 10 agent reports — co-existence "+
			"itself must not lose evidence", got, cspCount)
	}
}

// The evidence queue is still bounded on its own: sustained CSP traffic evicts
// the oldest violations rather than growing without limit.
func TestEvidenceQueueEvictsOldestWhenSaturated(t *testing.T) {
	h := NewReportHandler()

	docs := cspDocURLs(maxReports + 100)
	for _, doc := range docs {
		postCSPReport(t, h, doc)
	}

	reports := h.Reports()
	if len(reports) != maxReports {
		t.Fatalf("FAIL: ring = %d entries, want the maxReports=%d bound", len(reports), maxReports)
	}
	// Oldest-first eviction: the newest documents must be the survivors.
	last := reports[len(reports)-1]
	if last.URL != docs[len(docs)-1] {
		t.Fatalf("FAIL: newest CSP report (URL %q) is not retained; last is %q",
			docs[len(docs)-1], last.URL)
	}
}

// Class membership is decided by the ingest path, never the client-supplied
// Type: a telemetry POST claiming Type "csp_violation" must not be able to
// occupy (or evict from) the evidence queue.
func TestTelemetryCannotPromoteItselfIntoEvidenceQueue(t *testing.T) {
	h := NewReportHandler()

	postCSPReport(t, h, "https://example.com/real-violation")

	// Flood the evidence queue's class from the TELEMETRY endpoint.
	for i := range maxReports + 100 {
		postAgentReport(t, h, cspReportType, i)
	}

	reports := h.Reports()
	if len(reports) != maxReports {
		t.Fatalf("FAIL: ring = %d entries, want the maxReports=%d bound", len(reports), maxReports)
	}
	// The genuine violation must survive the spoofed flood.
	found := false
	for _, r := range reports {
		if r.URL == "https://example.com/real-violation" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("FAIL: a genuine CSP violation was evicted by %d telemetry reports that "+
			"claimed the csp_violation Type — class must come from the ingest path, not the payload",
			maxReports+100)
	}
}

// Reports() must present one chronological stream across both queues, since
// callers receive the merged view.
func TestReportsMergesQueuesChronologically(t *testing.T) {
	h := NewReportHandler()

	postCSPReport(t, h, "https://example.com/first")
	postAgentReport(t, h, "fetch", 1)
	postCSPReport(t, h, "https://example.com/third")
	postAgentReport(t, h, "fetch", 3)

	reports := h.Reports()
	if len(reports) != 4 {
		t.Fatalf("FAIL: Reports() = %d entries, want 4", len(reports))
	}
	wantURLs := []string{"https://example.com/first", agentReportURL, "https://example.com/third", agentReportURL}
	wantTypes := []string{cspReportType, "fetch", cspReportType, "fetch"}
	for i := range reports {
		if reports[i].Type != wantTypes[i] || reports[i].URL != wantURLs[i] {
			t.Fatalf("FAIL: Reports()[%d] = {Type:%q URL:%q}, want {Type:%q URL:%q}",
				i, reports[i].Type, reports[i].URL, wantTypes[i], wantURLs[i])
		}
	}
}

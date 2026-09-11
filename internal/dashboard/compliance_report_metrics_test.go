package dashboard

// Regression tests for round 14/25: handleComplianceReport must not
// fabricate compliance evidence. The pre-fix implementation hardcoded
// WAFUptimePct = 99.99 and LogCompletenessPct = 100.0 whenever
// TotalRequests > 0 — values nothing in the codebase measures — which made
// pci_dss_6_4_1, pci_dss_10_2_1 (PCI DSS Req 10.2.1 audit logging), and
// gdpr_art32 pass unconditionally, defeating the round 6/25 falsifiability
// fix end-to-end. Unmeasured metrics must stay zero and the controls they
// feed must fail honestly.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/compliance"
	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

func newComplianceReportDashboard(t *testing.T) (*Dashboard, func(framework string) compliance.Report) {
	t.Helper()
	cfg := &config.Config{Mode: "monitor", Listen: "127.0.0.1:0"}
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(1024), events.NewEventBus())
	if err != nil {
		t.Fatalf("engine setup: %v", err)
	}

	// Drive one request through the middleware so TotalRequests > 0 — the
	// exact condition that armed the fabrication.
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	traffic := httptest.NewServer(eng.Middleware(backend))
	resp, err := http.Get(traffic.URL + "/warmup")
	if err != nil {
		t.Fatalf("traffic setup: %v", err)
	}
	resp.Body.Close()
	t.Cleanup(traffic.Close)

	ce := compliance.NewEngine(config.ComplianceConfig{})
	d := &Dashboard{engine: eng, complianceEngine: ce}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/compliance/report/{framework}", d.handleComplianceReport)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	fetch := func(framework string) compliance.Report {
		t.Helper()
		resp, err := http.Get(srv.URL + "/api/v1/compliance/report/" + framework)
		if err != nil {
			t.Fatalf("report request (%s): %v", framework, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("report request (%s): HTTP %d, want 200", framework, resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		var report compliance.Report
		if err := json.Unmarshal(body, &report); err != nil {
			t.Fatalf("report (%s) is not valid JSON: %v", framework, err)
		}
		if len(report.Controls) == 0 {
			t.Fatalf("report (%s) evaluated zero controls", framework)
		}
		return report
	}
	return d, fetch
}

func complianceControlByID(report compliance.Report, id string) (compliance.ControlResult, bool) {
	for _, c := range report.Controls {
		if c.ID == id {
			return c, true
		}
	}
	return compliance.ControlResult{}, false
}

func TestComplianceReportDoesNotFabricateMetrics(t *testing.T) {
	_, fetch := newComplianceReportDashboard(t)

	pci := fetch("pci_dss")
	gdpr := fetch("gdpr")

	if c, ok := complianceControlByID(pci, "pci_dss_6_4_1"); ok && c.Status == "passing" {
		t.Fatalf("pci_dss_6_4_1 passed on waf_uptime_pct=99.99 — a value nothing measures; unmeasured metrics must stay zero and this control must fail honestly")
	}
	c1021, ok := complianceControlByID(pci, "pci_dss_10_2_1")
	if ok {
		if c1021.Status == "passing" {
			t.Fatalf("pci_dss_10_2_1 (PCI DSS Req 10.2.1 audit logging) passed on log_completeness_pct=100.0 — fabricated evidence defeating the round 6/25 falsifiability fix")
		}
		if v, ok := c1021.Evidence["log_completeness_pct"].(float64); ok && v == 100 {
			t.Fatalf("pci_dss_10_2_1 evidence carries the fabricated log_completeness_pct=100 constant")
		}
	}
	if c, ok := complianceControlByID(gdpr, "gdpr_art32"); ok && c.Status == "passing" {
		t.Fatalf("gdpr_art32 passed on the fabricated waf_uptime_pct=99.99")
	}
}

func TestComplianceReportStillGeneratesValidReport(t *testing.T) {
	_, fetch := newComplianceReportDashboard(t)

	pci := fetch("pci_dss")
	if pci.Framework != "pci_dss" {
		t.Fatalf("report framework = %q, want pci_dss", pci.Framework)
	}
	if pci.Summary.ControlsFailing == 0 && pci.Summary.ControlsPassing == 0 && pci.Summary.ControlsNotApplicable == 0 {
		t.Fatalf("report summary counts are all zero — control evaluation did not run")
	}
}

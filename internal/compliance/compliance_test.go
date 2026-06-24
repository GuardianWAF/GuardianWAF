package compliance

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

func goodMetrics() Metrics {
	return Metrics{
		WAFOperational:      true,
		WAFUptimePct:        99.99,
		TotalRequests:       45000000,
		BlockedRequests:     12450,
		LogCompletenessPct:  100.0,
		DLPBlocksInPeriod:   3,
		AlertCount:          42,
		AlertResponseP95Min: 15.0,
		TLSEnabled:          true,
		RateLimitActive:     true,
		IPACLActive:         true,
	}
}

func TestNewEngine(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: true})
	if e == nil {
		t.Fatal("expected engine, got nil")
	}
	if len(e.Controls()) == 0 {
		t.Error("expected builtin controls")
	}
}

func TestControlsForFramework(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: true})

	pci := e.ControlsForFramework(FrameworkPCI)
	if len(pci) == 0 {
		t.Error("expected PCI controls")
	}
	for _, c := range pci {
		found := false
		for _, fw := range c.Frameworks {
			if fw == FrameworkPCI {
				found = true
			}
		}
		if !found {
			t.Errorf("control %s not tagged with pci_dss", c.ID)
		}
	}

	gdpr := e.ControlsForFramework(FrameworkGDPR)
	if len(gdpr) == 0 {
		t.Error("expected GDPR controls")
	}

	unknown := e.ControlsForFramework("unknown_framework")
	if len(unknown) != 0 {
		t.Error("expected no controls for unknown framework")
	}
}

func TestEvaluate_PCI_Passing(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: true})
	results := e.Evaluate(FrameworkPCI, goodMetrics())

	if len(results) == 0 {
		t.Fatal("expected PCI results")
	}
	for _, r := range results {
		if r.Status != StatusPassing {
			t.Errorf("control %s: expected passing, got %s", r.ID, r.Status)
		}
	}
}

func TestEvaluate_PCI_Failing(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: true})
	m := goodMetrics()
	m.WAFUptimePct = 50.0 // Below 99.9% threshold

	results := e.Evaluate(FrameworkPCI, m)
	foundFailing := false
	for _, r := range results {
		if strings.Contains(r.ID, "6_4_1") && r.Status == StatusFailing {
			foundFailing = true
		}
	}
	if !foundFailing {
		t.Error("expected pci_dss_6_4_1 to fail with 50% uptime")
	}
}

func TestEvaluate_GDPR(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: true})
	results := e.Evaluate(FrameworkGDPR, goodMetrics())

	if len(results) == 0 {
		t.Fatal("expected GDPR results")
	}
	for _, r := range results {
		if r.Status != StatusPassing {
			t.Errorf("GDPR control %s: expected passing, got %s", r.ID, r.Status)
		}
	}
}

func TestEvaluate_SOC2_AlertResponseTooSlow(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: true})
	m := goodMetrics()
	m.AlertResponseP95Min = 120.0 // Exceeds 60-minute threshold

	results := e.Evaluate(FrameworkSOC2, m)
	for _, r := range results {
		if r.ID == "soc2_cc7_2" && r.Status != StatusFailing {
			t.Errorf("soc2_cc7_2 should fail with 120min response time, got %s", r.Status)
		}
	}
}

func TestEvaluate_ISO27001(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: true})
	results := e.Evaluate(FrameworkISO, goodMetrics())

	if len(results) < 2 {
		t.Fatalf("expected at least 2 ISO controls, got %d", len(results))
	}
	for _, r := range results {
		if r.Status != StatusPassing {
			t.Errorf("ISO control %s: expected passing, got %s", r.ID, r.Status)
		}
	}
}

func TestGenerateReport(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{
		Enabled:    true,
		Frameworks: []string{FrameworkPCI},
		AuditTrail: config.AuditTrailConfig{Enabled: true},
	})

	now := time.Now().UTC()
	period := Period{From: now.AddDate(0, -1, 0), To: now}
	report := e.GenerateReport(FrameworkPCI, "tenant001", period, goodMetrics())

	if report.Framework != FrameworkPCI {
		t.Errorf("framework = %s, want %s", report.Framework, FrameworkPCI)
	}
	if report.TenantID != "tenant001" {
		t.Errorf("tenant_id = %s, want tenant001", report.TenantID)
	}
	if report.Summary.OverallStatus != "passing" {
		t.Errorf("overall = %s, want passing", report.Summary.OverallStatus)
	}
	if report.Summary.ControlsPassing == 0 {
		t.Error("expected passing controls")
	}
	if report.ChainHash == "" {
		t.Error("expected chain hash with audit trail enabled")
	}
}

func TestGenerateReport_Partial(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: true})
	m := goodMetrics()
	m.WAFUptimePct = 50.0

	now := time.Now().UTC()
	report := e.GenerateReport(FrameworkPCI, "", Period{From: now, To: now}, m)

	if report.Summary.OverallStatus != "partial" && report.Summary.OverallStatus != "failing" {
		t.Errorf("expected partial or failing, got %s", report.Summary.OverallStatus)
	}
	if report.Summary.ControlsFailing == 0 {
		t.Error("expected failing controls")
	}
}

func TestGenerateReport_NoAuditTrail(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{
		Enabled:    true,
		AuditTrail: config.AuditTrailConfig{Enabled: false},
	})

	now := time.Now().UTC()
	report := e.GenerateReport(FrameworkPCI, "", Period{From: now, To: now}, goodMetrics())

	if report.ChainHash != "" {
		t.Error("expected no chain hash with audit trail disabled")
	}
}

func TestReportJSON(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: true})
	now := time.Now().UTC()
	report := e.GenerateReport(FrameworkGDPR, "", Period{From: now, To: now}, goodMetrics())

	data, err := ReportJSON(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("expected JSON output")
	}

	// Verify it's valid JSON
	var parsed Report
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Errorf("invalid JSON: %v", err)
	}
}

func TestReportCSV(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: true})
	now := time.Now().UTC()
	report := e.GenerateReport(FrameworkSOC2, "", Period{From: now, To: now}, goodMetrics())

	csv := ReportCSV(report)
	if !strings.Contains(csv, "control_id") {
		t.Error("expected CSV header")
	}
	if !strings.Contains(csv, StatusPassing) && !strings.Contains(csv, StatusFailing) {
		t.Error("expected status values in CSV")
	}
}

func TestAuditChain(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{
		Enabled:    true,
		AuditTrail: config.AuditTrailConfig{Enabled: true},
	})

	entry1 := e.AppendChain("test_event", map[string]string{"key": "value1"})
	if entry1.Index != 0 {
		t.Errorf("index = %d, want 0", entry1.Index)
	}
	if entry1.PrevHash != "genesis" {
		t.Errorf("prev_hash = %s, want genesis", entry1.PrevHash)
	}
	if entry1.Hash == "" {
		t.Error("expected non-empty hash")
	}

	entry2 := e.AppendChain("test_event", map[string]string{"key": "value2"})
	if entry2.Index != 1 {
		t.Errorf("index = %d, want 1", entry2.Index)
	}
	if entry2.PrevHash != entry1.Hash {
		t.Errorf("prev_hash mismatch: expected %s, got %s", entry1.Hash, entry2.PrevHash)
	}

	if e.ChainLen() != 2 {
		t.Errorf("chain len = %d, want 2", e.ChainLen())
	}
	if got := e.ChainHeadHash(); got != entry2.Hash {
		t.Errorf("chain head hash = %s, want %s", got, entry2.Hash)
	}
}

func TestVerifyChain(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{
		Enabled:    true,
		AuditTrail: config.AuditTrailConfig{Enabled: true},
	})

	e.AppendChain("event_a", "data_a")
	e.AppendChain("event_b", "data_b")
	e.AppendChain("event_c", 42)

	valid, errors := e.VerifyChain()
	if valid != 3 {
		t.Errorf("valid = %d, want 3", valid)
	}
	if len(errors) != 0 {
		t.Errorf("unexpected errors: %v", errors)
	}
}

func TestVerifyChain_Empty(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: true})
	valid, errors := e.VerifyChain()
	if valid != 0 {
		t.Errorf("expected 0 valid entries, got %d", valid)
	}
	if len(errors) != 0 {
		t.Errorf("expected no errors for empty chain, got %v", errors)
	}
}

func TestActiveFrameworks(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{
		Enabled:    true,
		Frameworks: []string{FrameworkPCI, FrameworkGDPR},
	})
	fw := e.ActiveFrameworks()
	if len(fw) != 2 {
		t.Fatalf("expected 2 frameworks, got %d", len(fw))
	}
	if fw[0] != FrameworkPCI || fw[1] != FrameworkGDPR {
		t.Errorf("unexpected frameworks: %v", fw)
	}
}

func TestActiveFrameworks_Default(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: true})
	fw := e.ActiveFrameworks()
	if len(fw) != 4 {
		t.Errorf("expected 4 default frameworks, got %d", len(fw))
	}
}

func TestCompareOperators(t *testing.T) {
	tests := []struct {
		val       float64
		op        string
		threshold float64
		expected  bool
	}{
		{100, ">=", 99.9, true},
		{99.8, ">=", 99.9, false},
		{50, "<=", 60, true},
		{70, "<=", 60, false},
		{5, ">", 0, true},
		{0, ">", 0, false},
		{100, "==", 100, true},
		{99, "==", 100, false},
	}
	for _, tt := range tests {
		result := compare(tt.val, tt.op, tt.threshold)
		if result != tt.expected {
			t.Errorf("compare(%v, %s, %v) = %v, want %v", tt.val, tt.op, tt.threshold, result, tt.expected)
		}
	}
}

func TestCollectEvidence(t *testing.T) {
	control := Control{
		Evidence: []EvidenceSpec{
			{Type: "waf_active"},
			{Type: "block_events"},
			{Type: "access_log_entries"},
			{Type: "dlp_events"},
		},
	}
	m := goodMetrics()
	ev := collectEvidence(control, m)

	if _, ok := ev["waf_operational"]; !ok {
		t.Error("expected waf_operational evidence")
	}
	if _, ok := ev["blocked_requests"]; !ok {
		t.Error("expected blocked_requests evidence")
	}
	if _, ok := ev["log_completeness_pct"]; !ok {
		t.Error("expected log_completeness_pct evidence")
	}
	if _, ok := ev["dlp_blocks"]; !ok {
		t.Error("expected dlp_blocks evidence")
	}
}

func TestSortedFrameworks(t *testing.T) {
	fw := SortedFrameworks()
	if len(fw) != 4 {
		t.Fatalf("expected 4 frameworks, got %d", len(fw))
	}
	for i := 1; i < len(fw); i++ {
		if fw[i] < fw[i-1] {
			t.Errorf("frameworks not sorted: %v", fw)
		}
	}
}

func TestGenerateReport_AllFrameworks(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: true})
	m := goodMetrics()
	now := time.Now().UTC()

	for _, fw := range SortedFrameworks() {
		report := e.GenerateReport(fw, "", Period{From: now, To: now}, m)
		if report.Framework != fw {
			t.Errorf("framework mismatch: %s != %s", report.Framework, fw)
		}
		if len(report.Controls) == 0 {
			t.Errorf("no controls for framework %s", fw)
		}
	}
}

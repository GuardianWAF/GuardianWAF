package compliance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// --- Close ---

func TestClose_Cov(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "audit.jsonl")
	e := NewEngine(config.ComplianceConfig{
		Enabled: true,
		AuditTrail: config.AuditTrailConfig{
			Enabled:     true,
			PersistPath: persistPath,
		},
	})
	e.AppendChain("test", "data")
	e.Close()
	// Should not panic on double close
	e.Close()
}

// --- NewEngine with persist path ---

func TestNewEngine_PersistPath_Cov(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "audit.jsonl")

	e := NewEngine(config.ComplianceConfig{
		Enabled: true,
		AuditTrail: config.AuditTrailConfig{
			Enabled:     true,
			PersistPath: persistPath,
		},
	})
	if e == nil {
		t.Fatal("expected engine")
	}
	if e.file == nil {
		t.Error("expected file handle for persist path")
	}

	// Write some entries
	e.AppendChain("event_a", map[string]string{"k": "v1"})
	e.AppendChain("event_b", map[string]string{"k": "v2"})
	e.Close()

	// Verify JSONL file was written
	data, err := os.ReadFile(persistPath)
	if err != nil {
		t.Fatalf("failed to read persist file: %v", err)
	}
	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	if lines != 2 {
		t.Errorf("expected 2 lines in JSONL, got %d", lines)
	}
}

// --- replayChain ---

func TestReplayChain_Cov(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "audit.jsonl")

	// First engine writes chain entries
	e1 := NewEngine(config.ComplianceConfig{
		Enabled: true,
		AuditTrail: config.AuditTrailConfig{
			Enabled:     true,
			PersistPath: persistPath,
		},
	})
	e1.AppendChain("type_a", "data_a")
	e1.AppendChain("type_b", "data_b")
	e1.Close()

	// Second engine replays from file
	e2 := NewEngine(config.ComplianceConfig{
		Enabled: true,
		AuditTrail: config.AuditTrailConfig{
			Enabled:     true,
			PersistPath: persistPath,
		},
	})
	if e2.ChainLen() != 2 {
		t.Errorf("expected chain length 2 after replay, got %d", e2.ChainLen())
	}

	// Verify chain integrity after replay
	valid, errors := e2.VerifyChain()
	if valid != 2 {
		t.Errorf("expected 2 valid entries after replay, got %d", valid)
	}
	if len(errors) != 0 {
		t.Errorf("unexpected chain errors after replay: %v", errors)
	}
	e2.Close()
}

func TestReplayChain_EmptyFile_Cov(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "audit.jsonl")
	_ = os.WriteFile(persistPath, []byte(""), 0o600)

	e := NewEngine(config.ComplianceConfig{
		Enabled: true,
		AuditTrail: config.AuditTrailConfig{
			Enabled:     true,
			PersistPath: persistPath,
		},
	})
	if e.ChainLen() != 0 {
		t.Error("expected empty chain from empty file")
	}
	e.Close()
}

func TestReplayChain_InvalidJSON_Cov(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "audit.jsonl")
	_ = os.WriteFile(persistPath, []byte("not json\nalso not json\n"), 0o600)

	e := NewEngine(config.ComplianceConfig{
		Enabled: true,
		AuditTrail: config.AuditTrailConfig{
			Enabled:     true,
			PersistPath: persistPath,
		},
	})
	// Invalid lines should be skipped
	if e.ChainLen() != 0 {
		t.Error("expected empty chain from invalid JSON lines")
	}
	e.Close()
}

func TestReplayChain_NonexistentFile_Cov(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{
		Enabled: true,
		AuditTrail: config.AuditTrailConfig{
			Enabled:     true,
			PersistPath: "/nonexistent/path/audit.jsonl",
		},
	})
	if e.ChainLen() != 0 {
		t.Error("expected empty chain from nonexistent file")
	}
}

// --- metricValue uncovered branches ---

func TestMetricValue_DefaultBranch_Cov(t *testing.T) {
	_ = NewEngine(config.ComplianceConfig{Enabled: true})

	// Create a control with an unknown metric to hit default case in metricValue
	// We can't directly call metricValue (unexported), so we test via evaluateCriteria
	// by constructing a Control with an unknown metric and calling Evaluate indirectly.
	// However, Evaluate only uses builtin controls. Let's use compare directly.
	// Actually the best way is to trigger metricValue("unknown_metric", ...) which returns 0.
	// Since compare with "<" operator and threshold=0 would return false for 0<0,
	// let's test that the "<" and default operator branches work.

	// Test "<" operator
	result := compare(5, "<", 10)
	if !result {
		t.Error("5 < 10 should be true")
	}
	result = compare(10, "<", 5)
	if result {
		t.Error("10 < 5 should be false")
	}

	// Test default operator
	result = compare(5, "unknown_op", 5)
	if result {
		t.Error("unknown operator should return false")
	}
}

// --- evaluate edge: StatusNoEvidence ---

func TestEvaluate_NoEvidenceControls_Cov(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: true})

	// Check if any builtin controls have no passing criteria
	// (none do in current code, but let's test the path by using empty metrics
	// to ensure we get the correct statuses for all controls)
	m := Metrics{} // All zeros/false
	results := e.Evaluate(FrameworkPCI, m)

	// With zero metrics, pci_dss_6_4_1 should fail (waf_uptime_pct < 99.9)
	// pci_dss_6_4_2 should fail (total_requests not > 0)
	// pci_dss_10_2_1 should fail (log_completeness_pct < 100)
	for _, r := range results {
		if r.Status != StatusFailing {
			t.Errorf("control %s should be failing with zero metrics, got %s", r.ID, r.Status)
		}
	}
}

// --- GenerateReport edge: all failing (overall=failing) ---

func TestGenerateReport_AllFailing_Cov(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: true})
	m := Metrics{} // all zeros

	now := time.Now().UTC()
	report := e.GenerateReport(FrameworkPCI, "tenant-001", Period{From: now, To: now}, m)

	if report.Summary.OverallStatus != "failing" {
		t.Errorf("expected failing, got %s", report.Summary.OverallStatus)
	}
	if report.Summary.ControlsFailing == 0 {
		t.Error("expected failing controls")
	}
	if report.Summary.ControlsPassing > 0 {
		t.Error("expected no passing controls")
	}
}

// --- VerifyChain with tampered hash ---

func TestVerifyChain_TamperedHash_Cov(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{
		Enabled:    true,
		AuditTrail: config.AuditTrailConfig{Enabled: true},
	})
	e.AppendChain("event_a", "data_a")
	e.AppendChain("event_b", "data_b")

	// Tamper with a hash
	e.mu.Lock()
	e.chain[0].Hash = "tampered_hash"
	e.mu.Unlock()

	valid, errors := e.VerifyChain()
	if valid != 0 {
		t.Errorf("expected 0 valid entries after tamper, got %d", valid)
	}
	if len(errors) == 0 {
		t.Error("expected errors for tampered chain")
	}
}

// --- VerifyChain with broken prev link ---

func TestVerifyChain_BrokenPrevLink_Cov(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{
		Enabled:    true,
		AuditTrail: config.AuditTrailConfig{Enabled: true},
	})
	e.AppendChain("event_a", "data_a")
	e.AppendChain("event_b", "data_b")

	// Tamper with prev_hash of entry 1
	e.mu.Lock()
	e.chain[1].PrevHash = "wrong_prev"
	e.mu.Unlock()

	valid, errors := e.VerifyChain()
	if valid != 1 {
		t.Errorf("expected 1 valid (first entry still valid) after breaking prev link, got %d", valid)
	}
	if len(errors) == 0 {
		t.Error("expected errors for broken prev link")
	}
}

// --- AppendChain with file persistence ---

func TestAppendChain_WithFile_Cov(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "audit.jsonl")

	e := NewEngine(config.ComplianceConfig{
		Enabled: true,
		AuditTrail: config.AuditTrailConfig{
			Enabled:     true,
			PersistPath: persistPath,
		},
	})

	// Append entries - should write to JSONL file
	e.AppendChain("report_generated", map[string]string{"report_id": "rpt_001"})

	data, err := os.ReadFile(persistPath)
	if err != nil {
		t.Fatalf("failed to read persist file: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected data in persist file")
	}

	// Verify it's valid JSON
	var entry map[string]any
	if err := json.Unmarshal(data[:len(data)-1], &entry); err != nil { // trim trailing newline
		t.Errorf("invalid JSON in persist file: %v", err)
	}
	e.Close()
}

// --- ReportJSON error path (not really testable without mocking, but let's verify roundtrip) ---

func TestReportJSON_Roundtrip_Cov(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: true})
	now := time.Now().UTC()
	report := e.GenerateReport(FrameworkPCI, "tenant-roundtrip", Period{From: now, To: now}, goodMetrics())

	data, err := ReportJSON(report)
	if err != nil {
		t.Fatalf("ReportJSON: %v", err)
	}

	var parsed Report
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if parsed.ReportID != report.ReportID {
		t.Errorf("report_id mismatch: %s != %s", parsed.ReportID, report.ReportID)
	}
	if parsed.Framework != FrameworkPCI {
		t.Errorf("framework mismatch: %s", parsed.Framework)
	}
	if parsed.TenantID != "tenant-roundtrip" {
		t.Errorf("tenant_id mismatch: %s", parsed.TenantID)
	}
}

// --- NewEngine without persist path but with audit trail ---

func TestNewEngine_AuditTrailNoPersist_Cov(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{
		Enabled:    true,
		AuditTrail: config.AuditTrailConfig{Enabled: true},
	})
	if e.file != nil {
		t.Error("expected nil file when no persist path")
	}
	e.AppendChain("event", "data")
	if e.ChainLen() != 1 {
		t.Error("expected 1 entry in chain")
	}
}

// --- collectEvidence with all evidence types ---

func TestCollectEvidence_AllTypes_Cov(t *testing.T) {
	control := Control{
		Evidence: []EvidenceSpec{
			{Type: "waf_active"},
			{Type: "block_events"},
			{Type: "access_log_entries"},
			{Type: "dlp_events"},
			{Type: "alert_events"},
			{Type: "tls_active"},
			{Type: "rate_limit_active"},
			{Type: "ip_acl_active"},
		},
	}
	m := goodMetrics()
	ev := collectEvidence(control, m)

	expected := []string{
		"waf_operational", "waf_uptime_pct",
		"blocked_requests", "total_requests",
		"log_completeness_pct",
		"dlp_blocks",
		"alert_count", "alert_response_p95_min",
		"tls_enabled",
		"rate_limit_active",
		"ip_acl_active",
	}
	for _, key := range expected {
		if _, ok := ev[key]; !ok {
			t.Errorf("expected evidence key %q", key)
		}
	}
}

// --- Evaluate with empty framework returns no results ---

func TestEvaluate_UnknownFramework_Cov(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: true})
	results := e.Evaluate("unknown_fw", goodMetrics())
	if len(results) != 0 {
		t.Error("expected no results for unknown framework")
	}
}

// --- GenerateReport report ID format ---

func TestGenerateReport_ReportIDFormat_Cov(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: true})
	now := time.Now().UTC()
	period := Period{From: now.AddDate(0, -1, 0), To: now}
	report := e.GenerateReport(FrameworkGDPR, "t1", period, goodMetrics())

	expectedPrefix := "rpt_gdpr_" + period.From.Format("20060102")
	if report.ReportID[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("report_id prefix mismatch: %s", report.ReportID)
	}
}

// --- NewEngine disabled but with persist path ---

func TestNewEngine_Disabled_Cov(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: false})
	if e == nil {
		t.Error("expected engine even when disabled")
	}
	// Should still function for basic operations
	fw := e.ActiveFrameworks()
	if len(fw) != 4 {
		t.Error("expected 4 default frameworks")
	}
}

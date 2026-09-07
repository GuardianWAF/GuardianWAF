package compliance

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

func newAuditTestConfig(t *testing.T) config.ComplianceConfig {
	t.Helper()
	return config.ComplianceConfig{
		Enabled: true,
		AuditTrail: config.AuditTrailConfig{
			Enabled:     true,
			PersistPath: filepath.Join(t.TempDir(), "audit.jsonl"),
		},
	}
}

// TestChainVerifiesAfterRestart pins the tamper-evidence contract: entries
// hashed at append time must still verify after close + reopen. AppendChain
// previously hashed the ORIGINAL Go value's JSON encoding (struct fields in
// declaration order), while replayChain unmarshals entries into a generic map
// and VerifyChain re-marshals with alphabetically sorted keys — a different
// byte string, so every replayed entry failed verification after a restart.
func TestChainVerifiesAfterRestart(t *testing.T) {
	cfg := newAuditTestConfig(t)

	e1, err := NewEngineWithError(cfg)
	if err != nil {
		t.Fatalf("NewEngineWithError: %v", err)
	}
	period := Period{
		From: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC),
	}
	if _, err := e1.GenerateReportWithError("pci_dss", "", period, Metrics{
		WAFOperational:     true,
		WAFUptimePct:       100,
		TotalRequests:      100,
		BlockedRequests:    10,
		LogCompletenessPct: 100,
	}); err != nil {
		t.Fatalf("GenerateReportWithError: %v", err)
	}
	if err := e1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	e2, err := NewEngineWithError(cfg)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer e2.Close()

	if e2.ChainLen() != 1 {
		t.Fatalf("ChainLen = %d; want 1", e2.ChainLen())
	}
	valid, errs := e2.VerifyChain()
	if len(errs) != 0 || valid != 1 {
		t.Fatalf("VerifyChain after restart: valid=%d errors=%v; want valid=1, no errors", valid, errs)
	}
}

// TestChainVerifiesMixedDataTypesAfterRestart covers the secondary branches:
// struct-typed and map-typed data, plus a nil-data entry, must all survive a
// restart and verify in order.
func TestChainVerifiesMixedDataTypesAfterRestart(t *testing.T) {
	cfg := newAuditTestConfig(t)

	e1, err := NewEngineWithError(cfg)
	if err != nil {
		t.Fatalf("NewEngineWithError: %v", err)
	}
	if _, err := e1.AppendChainWithError("struct_entry", Report{
		ReportID:  "rpt_x",
		Framework: FrameworkPCI,
		Summary:   ReportSummary{ControlsPassing: 2, OverallStatus: "passing"},
	}); err != nil {
		t.Fatalf("AppendChainWithError(struct): %v", err)
	}
	if _, err := e1.AppendChainWithError("map_entry", map[string]any{"key": "value", "count": 3}); err != nil {
		t.Fatalf("AppendChainWithError(map): %v", err)
	}
	if _, err := e1.AppendChainWithError("nil_entry", nil); err != nil {
		t.Fatalf("AppendChainWithError(nil): %v", err)
	}
	if valid, errs := e1.VerifyChain(); len(errs) != 0 || valid != 3 {
		t.Fatalf("in-memory verify: valid=%d errors=%v; want 3, none", valid, errs)
	}
	if err := e1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	e2, err := NewEngineWithError(cfg)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer e2.Close()

	if e2.ChainLen() != 3 {
		t.Fatalf("ChainLen = %d; want 3", e2.ChainLen())
	}
	valid, errs := e2.VerifyChain()
	if len(errs) != 0 || valid != 3 {
		t.Fatalf("VerifyChain after restart: valid=%d errors=%v; want 3, none", valid, errs)
	}
}

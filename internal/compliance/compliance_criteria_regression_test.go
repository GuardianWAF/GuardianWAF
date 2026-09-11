package compliance

// Regression tests for the compliance control criteria contract (round
// round6-gdpr-dlp-tautology). A control criterion must be falsifiable:
// gdpr_art32_dlp ("DLP blocks present") previously used
// dlp_blocks_in_period >= 0 on a non-negative counter — a tautology that
// could never fail, so every report passed the control regardless of
// evidence, overstating GDPR compliance.

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

func TestGDPRDLPCriteriaRequiresBlocks(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{})

	// Zero DLP blocks — the control's evidence spec requires "DLP blocks
	// present", so the control must fail.
	empty := e.Evaluate(FrameworkGDPR, Metrics{WAFOperational: true, WAFUptimePct: 100, TotalRequests: 5000})
	dlpStatus := ""
	for _, r := range empty {
		if r.ID == "gdpr_art32_dlp" {
			dlpStatus = r.Status
		}
	}
	if dlpStatus != StatusFailing {
		t.Fatalf("gdpr_art32_dlp = %q with zero DLP blocks, want %q (the criterion must be falsifiable)", dlpStatus, StatusFailing)
	}

	// DLP blocks present — the control passes.
	active := e.Evaluate(FrameworkGDPR, Metrics{WAFOperational: true, WAFUptimePct: 100, TotalRequests: 5000, DLPBlocksInPeriod: 3})
	for _, r := range active {
		if r.ID == "gdpr_art32_dlp" && r.Status != StatusPassing {
			t.Fatalf("gdpr_art32_dlp = %q with 3 DLP blocks, want %q", r.Status, StatusPassing)
		}
	}
}

func TestPCILogCompletenessBoundary(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{})

	// Exactly 100% passes (pci_dss_10_2_1: log_completeness_pct >= 100).
	full := e.Evaluate(FrameworkPCI, Metrics{LogCompletenessPct: 100})
	status := ""
	for _, r := range full {
		if r.ID == "pci_dss_10_2_1" {
			status = r.Status
		}
	}
	if status != StatusPassing {
		t.Fatalf("pci_dss_10_2_1 = %q at exactly 100%% completeness, want %q", status, StatusPassing)
	}

	// 99.9% fails the >= 100 threshold.
	partial := e.Evaluate(FrameworkPCI, Metrics{LogCompletenessPct: 99.9})
	for _, r := range partial {
		if r.ID == "pci_dss_10_2_1" && r.Status != StatusFailing {
			t.Fatalf("pci_dss_10_2_1 = %q at 99.9%% completeness, want %q", r.Status, StatusFailing)
		}
	}
}

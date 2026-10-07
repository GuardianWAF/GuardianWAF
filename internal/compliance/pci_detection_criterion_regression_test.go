package compliance

// Regression: pci_dss_6_4_2 ("PCI DSS v4.0 Req 6.4.2 — Attack detection and
// prevention") must be falsifiable by its own blocked-attack evidence.
//
// The control declares evidence {Type: "block_events", Description: "Attacks
// detected and blocked"}, and collectEvidence surfaces blocked_requests for
// exactly that spec (compliance.go:560). Its sole criterion nevertheless read
// {total_requests > 0}, which only asserts the WAF served some traffic — so a
// WAF with detection and prevention entirely inert graded this control PASSING
// and inflated the PCI DSS attestation, no matter how many requests it served
// and no matter that it blocked zero attacks.
//
// This is the same defect class the sibling gdpr_art32_dlp criterion already
// documents in this package: a criterion must test the evidence it declares, or
// the control cannot fail.

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// pciStatus is a small lookup helper so each test reads as one assertion.
func pciStatus(t *testing.T, e *Engine, m Metrics, id string) string {
	t.Helper()
	for _, r := range e.Evaluate(FrameworkPCI, m) {
		if r.ID == id {
			return r.Status
		}
	}
	t.Fatalf("control %q not present in the PCI framework result set", id)
	return ""
}

// TestPCIDetectionCriterionRequiresBlockedAttacks is the exact trigger from the
// proof: high traffic volume, zero blocked attacks.
func TestPCIDetectionCriterionRequiresBlockedAttacks(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: true})

	inert := Metrics{
		WAFOperational:     true,
		WAFUptimePct:       100,
		TotalRequests:      1_000_000,
		BlockedRequests:    0,
		LogCompletenessPct: 100,
	}

	if got := pciStatus(t, e, inert, "pci_dss_6_4_2"); got != StatusFailing {
		t.Fatalf("pci_dss_6_4_2 = %q with 1,000,000 requests and 0 blocked attacks, "+
			"want %q — the criterion must test detection/prevention, not traffic "+
			"volume", got, StatusFailing)
	}
}

// TestPCIDetectionCriterionBoundary pins both sides of the > 0 threshold.
func TestPCIDetectionCriterionBoundary(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: true})

	base := Metrics{
		WAFOperational:     true,
		WAFUptimePct:       100,
		TotalRequests:      1_000_000,
		LogCompletenessPct: 100,
	}

	// Exactly one blocked attack clears the threshold.
	one := base
	one.BlockedRequests = 1
	if got := pciStatus(t, e, one, "pci_dss_6_4_2"); got != StatusPassing {
		t.Errorf("pci_dss_6_4_2 = %q with exactly 1 blocked attack, want %q", got, StatusPassing)
	}

	// Zero fails even when total_requests is enormous — the boundary the old
	// {total_requests > 0} criterion inverted.
	zero := base
	zero.BlockedRequests = 0
	if got := pciStatus(t, e, zero, "pci_dss_6_4_2"); got != StatusFailing {
		t.Errorf("pci_dss_6_4_2 = %q with 0 blocked attacks and 1,000,000 requests, "+
			"want %q", got, StatusFailing)
	}
}

// TestPCIDetectionCriterionIgnoresTrafficOnly is the control for this round: the
// change must not make the control sensitive to traffic volume. Doubling
// total_requests with no blocked attacks must not flip the verdict, and the
// neighbouring uptime-based control must be untouched.
func TestPCIDetectionCriterionIgnoresTrafficOnly(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: true})

	low := Metrics{WAFOperational: true, WAFUptimePct: 100, TotalRequests: 10, BlockedRequests: 0}
	high := Metrics{WAFOperational: true, WAFUptimePct: 100, TotalRequests: 9_000_000, BlockedRequests: 0}

	if gotLow, gotHigh := pciStatus(t, e, low, "pci_dss_6_4_2"), pciStatus(t, e, high, "pci_dss_6_4_2"); gotLow != gotHigh {
		t.Errorf("pci_dss_6_4_2 verdict tracks traffic volume: %q at 10 requests vs "+
			"%q at 9,000,000 requests with zero blocked attacks — it must depend only "+
			"on blocked attacks", gotLow, gotHigh)
	}

	// The neighbouring "WAF in place" control still grades on uptime only.
	if got := pciStatus(t, e, Metrics{WAFUptimePct: 100}, "pci_dss_6_4_1"); got != StatusPassing {
		t.Errorf("pci_dss_6_4_1 = %q at waf_uptime_pct=100, want %q (unrelated "+
			"control must be unaffected)", got, StatusPassing)
	}
}

// TestPCIDetectionEvidenceStillSurfaced guards the other half of the contract:
// the control must still collect and report its blocked-attack evidence, since
// an auditor reads that field alongside the verdict.
func TestPCIDetectionEvidenceStillSurfaced(t *testing.T) {
	e := NewEngine(config.ComplianceConfig{Enabled: true})
	m := Metrics{WAFOperational: true, WAFUptimePct: 100, TotalRequests: 500, BlockedRequests: 7}

	for _, r := range e.Evaluate(FrameworkPCI, m) {
		if r.ID != "pci_dss_6_4_2" {
			continue
		}
		if v, ok := r.Evidence["blocked_requests"].(int64); !ok || v != 7 {
			t.Errorf("pci_dss_6_4_2 evidence blocked_requests = %v (type %T), want 7",
				r.Evidence["blocked_requests"], r.Evidence["blocked_requests"])
		}
		if r.Status != StatusPassing {
			t.Errorf("pci_dss_6_4_2 = %q with 7 blocked attacks, want %q", r.Status, StatusPassing)
		}
		return
	}
	t.Fatal("pci_dss_6_4_2 missing from the PCI result set")
}

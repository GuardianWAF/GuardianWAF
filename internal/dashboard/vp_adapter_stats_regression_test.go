package dashboard

// Regression (round 2026-10-13-r8-vpstats-totalcves): virtualPatchAdapter.
// GetStats hardcoded TotalCVEs: 0 while mapping TotalPatches,
// ActivePatches, and BySeverity from the layer's DatabaseStats — so
// /api/virtualpatch/stats always reported an empty CVE database
// (total_cves=0) even though the shipped defaults alone are four CVE
// entries and NVD sync adds more. The adapter is the production mapping
// site (the virtualPatchOverride stub path already passes its count
// through); it must mirror the layer's stats instead of dropping fields.

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/layers/virtualpatch"
)

func TestVirtualPatchAdapterStatsCarryCVECount(t *testing.T) {
	// Real layer: NewLayer loads the four shipped default CVE entries
	// (no auto-update goroutine — AutoUpdate is unset).
	layer := virtualpatch.NewLayer(&virtualpatch.Config{Enabled: true})
	adapter := &virtualPatchAdapter{layer: layer}

	got, want := adapter.GetStats(), layer.GetStats()

	if want.TotalCVEs == 0 {
		t.Fatalf("control: layer unexpectedly holds no default CVE entries")
	}
	if got.TotalCVEs != want.TotalCVEs {
		t.Fatalf("adapter stats dropped the CVE count: adapter total_cves=%d, layer total_cves=%d", got.TotalCVEs, want.TotalCVEs)
	}
	if got.TotalPatches != want.TotalPatches || got.ActivePatches != want.ActivePatches {
		t.Fatalf("adapter stats diverged from the layer: adapter=%+v, layer=%+v", got, want)
	}
}

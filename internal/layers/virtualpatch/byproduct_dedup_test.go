package virtualpatch

import "testing"

// Regression tests: Database.AddCVE must deduplicate the byProduct index —
// AddCVE runs on every NVD refresh for every CVE in the rolling window, and
// the previous unconditional append accumulated a duplicate CVEID per
// refresh (index bloat; GetPatchesForProduct returned the same patch
// multiplied).

func dedupTestEntry(cveID, cpe string) *CVEEntry {
	return &CVEEntry{
		CVEID:  cveID,
		Active: true,
		Patches: []VirtualPatch{{
			ID:      "VP-" + cveID,
			CVEID:   cveID,
			Action:  "block",
			Enabled: true,
			Patterns: []PatchPattern{
				{Type: "path", Pattern: "/vulnerable", MatchType: "contains"},
			},
		}},
		AffectedProducts: []Product{
			{Vendor: "acme", Product: "widget", Version: "1.0", CPE: cpe, Vulnerable: true},
		},
	}
}

const dedupCPE = "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"

func TestAddCVEDeduplicatesProductIndex(t *testing.T) {
	db := NewDatabase()

	// Two refreshes re-adding the SAME CVE must keep one index entry.
	db.AddCVE(dedupTestEntry("CVE-2024-0001", dedupCPE))
	db.AddCVE(dedupTestEntry("CVE-2024-0001", dedupCPE))

	if got := len(db.GetPatchesForProduct(dedupCPE)); got != 1 {
		t.Fatalf("FAIL: duplicate re-add produced %d index entries (want 1)", got)
	}

	// Distinct CVEs under the same CPE each get their own entry.
	db.AddCVE(dedupTestEntry("CVE-2024-0002", dedupCPE))
	if got := len(db.GetPatchesForProduct(dedupCPE)); got != 2 {
		t.Fatalf("FAIL: distinct CVEs indexed as %d entries (want 2)", got)
	}

	// An unrelated CPE stays clean.
	if got := db.GetPatchesForProduct("cpe:2.3:a:other:gadget:1.0:*:*:*:*:*:*:*"); len(got) != 0 {
		t.Fatalf("FAIL: unrelated CPE returned %d patches (want 0)", len(got))
	}
}

func TestAddCVEDuplicateReAddKeepsPatchState(t *testing.T) {
	// Re-adding must not lose or corrupt the stored patch.
	db := NewDatabase()
	db.AddCVE(dedupTestEntry("CVE-2024-0003", dedupCPE))
	db.AddCVE(dedupTestEntry("CVE-2024-0003", dedupCPE))

	patches := db.GetPatchesForProduct(dedupCPE)
	if len(patches) != 1 {
		t.Fatalf("FAIL: expected 1 patch after duplicate re-add, got %d", len(patches))
	}
	if patches[0].ID != "VP-CVE-2024-0003" || !patches[0].Enabled {
		t.Fatalf("FAIL: stored patch corrupted after re-add: ID=%q enabled=%v", patches[0].ID, patches[0].Enabled)
	}
}

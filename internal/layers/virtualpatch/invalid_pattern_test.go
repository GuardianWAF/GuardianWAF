package virtualpatch

import "testing"

// Regression: AddPatch accepted virtual patches whose regex patterns do
// not compile. Such a patch is applied and enabled, but matchRegex's
// compile failure silently returns false on every request — the CVE the
// patch exists to block stays exploitable with no log and no state change.
// Ingestion must flag the patch (disabled + pending review semantics)
// instead of applying it inertly.
func TestAddPatchInvalidRegexDisabledNotApplied(t *testing.T) {
	l := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL"},
	})

	patch := &VirtualPatch{
		ID:         "VP-INVALID-REGEX",
		CVEID:      "CVE-2099-0001",
		Name:       "broken pattern",
		Action:     "block",
		Score:      100,
		Severity:   "CRITICAL",
		Enabled:    true,
		MatchLogic: "or",
		Patterns: []PatchPattern{
			{Type: "path", MatchType: "regex", Pattern: "(unclosed["},
		},
	}
	l.AddPatch(patch)

	if patch.Enabled {
		t.Fatalf("FAIL: patch with uncompilable regex left enabled — it will be silently inert on every request")
	}
	if patch.ReviewStatus != "disabled" {
		t.Fatalf("FAIL: expected ReviewStatus %q for invalid regex, got %q", "disabled", patch.ReviewStatus)
	}

	// Control: a valid regex patch still applies normally.
	okPatch := &VirtualPatch{
		ID:         "VP-OK",
		CVEID:      "CVE-2099-0002",
		Name:       "valid pattern",
		Action:     "block",
		Score:      100,
		Severity:   "CRITICAL",
		Enabled:    true,
		MatchLogic: "or",
		Patterns: []PatchPattern{
			{Type: "path", MatchType: "regex", Pattern: "^/vulnerable/[0-9]+$"},
		},
	}
	l.AddPatch(okPatch)
	if !okPatch.Enabled {
		t.Fatalf("FAIL: valid patch was disabled")
	}
	if okPatch.ReviewStatus != "applied" {
		t.Fatalf("FAIL: valid patch ReviewStatus = %q, want applied", okPatch.ReviewStatus)
	}
}

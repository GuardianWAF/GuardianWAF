package cmdi

// Regression (bug-hunt round 2026-09-18-r14, extending the asymmetry-sweep
// family from the round-9/25 sweep note): extractFirstWord split candidate
// command names on WHITESPACE ONLY, while the shell treats < and > as word
// boundaries (redirection). checkRedirection handled only the OUTPUT form
// (>), so the no-space INPUT-redirection bypass —
// `127.0.0.1;cat</etc/passwd` — extracted "cat</etc/passwd" as the command
// name, matched nothing in commandDatabase (exact-match lookups), and scored
// ZERO: every check silent, request passed in enforce mode. The whitespace
// twin `127.0.0.1;cat /etc/passwd` was classified (recon: cat, 75, blocked).
// The codebase already acknowledged < as a redirection boundary in
// hasCommandArguments (rest[0]=='<' counts as an argument signal) — the
// extraction just never did.
//
// Fix: extractFirstWord also splits on < and >. Callers only reach it after
// an attack-context prefix (separator, substitution, encoded newline), so
// prose comparisons (a<b) never reach extraction.

import (
	"strings"
	"testing"
)

// TestDetect_InputRedirectionNoSpaceBypassDetected is the defect case: the
// no-space input-redirection form must be classified like its whitespace twin.
func TestDetect_InputRedirectionNoSpaceBypassDetected(t *testing.T) {
	findings := Detect("127.0.0.1;cat</etc/passwd", "query")
	if len(findings) == 0 {
		t.Fatalf("FAIL: `;cat</etc/passwd` (no-space input redirection) produced 0 findings — the shell treats < as a word boundary, so the command is `cat`; the payload must be classified like the whitespace form")
	}
}

// Control: the whitespace form keeps its classification.
func TestDetect_SpaceFormStillDetected(t *testing.T) {
	findings := Detect("127.0.0.1;cat /etc/passwd", "query")
	if len(findings) == 0 {
		t.Fatalf("FAIL: harness control — the whitespace form must keep its finding, got none")
	}
}

// TestDetect_OutputRedirectionNoSpaceMetacharClassified: the no-space OUTPUT
// form `;id>/tmp/out` previously scored only the 45-score redirection crumb
// (below the block threshold) with the command invisible; the metachar
// classification must fire for it too.
func TestDetect_OutputRedirectionNoSpaceMetacharClassified(t *testing.T) {
	findings := Detect("127.0.0.1;id>/tmp/out", "query")
	found := false
	for _, f := range findings {
		if strings.Contains(f.Description, "with command detected") {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: `;id>/tmp/out` produced %d findings, none with the metachar command classification (%+v)", len(findings), findings)
	}
}

// Control: prose comparisons with angle brackets and no shell separator
// produce no metachar command findings — the extraction only runs after an
// attack-context prefix.
func TestDetect_ComparisonAngleBracketsBenign(t *testing.T) {
	findings := Detect("if a<b then a>0", "query")
	for _, f := range findings {
		if strings.Contains(f.Description, "with command detected") {
			t.Fatalf("FAIL: harness control — prose with angle brackets must not produce a metachar command finding, got %+v", f)
		}
	}
}

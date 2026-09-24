package sqli

// Regression (round 2026-09-24-r11-comment-adjacency): checkCharConcat and
// checkSubquery located their anchor tokens with an immediate i+1 adjacency
// check instead of the comment-skipping lookaheads every other check uses.
// Comments are whitespace to the SQL parser — CONCAT/**/(0x7e) and
// (/**/SELECT 1) both EXECUTE — and filterSignificant keeps Comment tokens
// in the analysis list, so these shapes evaded their checks entirely (zero
// findings / no subquery finding). Post-fix both lookaheads skip Comment
// tokens, honoring the version-comment fix's contract ("every lookahead
// already skips Comment tokens").

import (
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func hasFinding(findings []engine.Finding, score int, descPart string) bool {
	for _, f := range findings {
		if f.Score == score && strings.Contains(f.Description, descPart) {
			return true
		}
	}
	return false
}

func TestDetect_CommentTransparentAdjacency(t *testing.T) {
	// CHAR/CONCAT obfuscation with an inline comment between the function
	// name and its paren — executes on any MySQL target.
	findings := Detect("CONCAT/**/(0x7e)", "args")
	if !hasFinding(findings, 50, "obfuscation using CONCAT()") {
		t.Fatalf("CONCAT/**/(0x7e) findings = %d, want the 50-score obfuscation finding", len(findings))
	}

	// Subquery with a comment between ( and SELECT.
	findings = Detect("(/**/SELECT 1)", "args")
	if !hasFinding(findings, 25, "Subquery injection pattern") {
		t.Fatalf("(/**/SELECT 1) findings = %d, want the 25-score subquery finding", len(findings))
	}

	// Controls: the comment-free forms keep firing.
	findings = Detect("CONCAT(0x7e)", "args")
	if !hasFinding(findings, 50, "obfuscation using CONCAT()") {
		t.Fatalf("CONCAT(0x7e) findings = %d, want the 50-score obfuscation finding", len(findings))
	}
	findings = Detect("(SELECT 1)", "args")
	if !hasFinding(findings, 25, "Subquery injection pattern") {
		t.Fatalf("(SELECT 1) findings = %d, want the 25-score subquery finding", len(findings))
	}
}

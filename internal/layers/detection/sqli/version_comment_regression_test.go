package sqli

// Regression (bug-hunt round 2026-09-18-r12, extending the asymmetry-sweep
// family from the round-9/25 sweep note): the tokenizer's comment branch
// treated EVERY `/* ... */` block as an inert comment, including MySQL's
// EXECUTABLE version-comment form `/*! ... */`. MySQL parses version-comment
// content as SQL whenever the server meets the embedded minimum (in practice
// always), so `/*!50000UNION*//*!50000SELECT*/` executes the union on any
// MySQL target while the tokenizer classified both blocks as Comment tokens —
// checkUnionSelect saw no UNION/SELECT keywords and the payload scored only
// the 35-score loose-comment crumb, passing in enforce mode.
//
// Fix: `/*!<digits>` is emitted as the comment prefix (comment token) and the
// block content is tokenized as normal SQL; a stray closing `*/` reached in
// the main loop is emitted as comment residue (a Comment token every
// lookahead already skips), so keyword adjacency survives per-keyword block
// splitting. Plain `/* ... */` comments and the whole-block tight shape keep
// their existing behavior.

import (
	"testing"
)

const versionCommentPayload = "1' foo/*!50000UNION*//*!50000SELECT*/password FROM users--"

// TestDetect_VersionCommentSplitUnionDetected is the defect case: the
// sqlmap-style per-keyword version-comment split must still yield the
// union-select classification.
func TestDetect_VersionCommentSplitUnionDetected(t *testing.T) {
	findings := Detect(versionCommentPayload, "body")
	found := false
	for _, f := range findings {
		if f.Description == "UNION SELECT injection pattern detected" {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: MySQL version-comment union payload produced %d findings, none with the UNION SELECT classification (%+v) — executable /*! blocks must not be classified as inert comments", len(findings), findings)
	}
}

// TestDetect_VersionCommentOneBlockUnionDetected: the single-block form
// `/*!50000UNION ALL SELECT*/` must classify the union too (pre-fix it only
// scored the 60 tight-comment crumb, with the union itself invisible).
func TestDetect_VersionCommentOneBlockUnionDetected(t *testing.T) {
	findings := Detect("1' /*!50000UNION ALL SELECT*/ password FROM users--", "body")
	found := false
	for _, f := range findings {
		if f.Description == "UNION SELECT injection pattern detected" {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: single-block version-comment union produced %d findings, none with the UNION SELECT classification (%+v)", len(findings), findings)
	}
}

// Control: a PLAIN block comment between the keywords keeps working — the
// existing comment-skipping lookahead must not regress.
func TestDetect_UnionPlainBlockCommentStillDetected(t *testing.T) {
	findings := Detect("1' UNION /*noise*/ SELECT password FROM users--", "body")
	found := false
	for _, f := range findings {
		if f.Description == "UNION SELECT injection pattern detected" {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: harness control — plain block comment between UNION and SELECT must still yield the union finding, got %+v", findings)
	}
}

// Control: prose inside a version comment must not fabricate a union finding.
func TestDetect_ProseVersionCommentNoUnionFinding(t *testing.T) {
	findings := Detect("/*! jquery example template banner */", "body")
	for _, f := range findings {
		if f.Description == "UNION SELECT injection pattern detected" {
			t.Fatalf("FAIL: harness control — prose version comment must not produce a union finding, got %+v", f)
		}
	}
}

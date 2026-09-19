package lfi

// Regression (bug-hunt round 2026-09-18-r15, extending the asymmetry-sweep
// family from the round-9/25 sweep note): buildSensitivePathTrie ingested
// the full Linux list (33 paths), the full Windows list (20 paths — made
// reachable by the round-35 lowercase-at-insertion fix), and only FOUR of
// the 15 declared macOS paths from sensitive_paths.go macosSensitivePaths.
// The /private/etc/* forms of the remaining entries are covered implicitly —
// the trie's restart-at-root walk finds the embedded /etc/* suffix and fires
// the Linux classification — but SEVEN declared entries have no reachable
// embedded suffix and produced ZERO findings: /private/var/log/system.log,
// /private/var/log/asl, /var/log/system.log, /var/log/install.log,
// /Library/Logs/DiagnosticReports,
// /Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist,
// and /Users/Shared. An absolute-path read (?file=/var/log/install.log — no
// traversal needed) therefore scored zero on a macOS deployment.

import (
	"strings"
	"testing"
)

// missingMacOSPaths are the declared-but-untrieged macOS sensitive paths,
// each with the score tier of its closest Linux/Windows analog
// (passwd-class 90/95, logs 60, config/directory 55).
func TestDetect_MacOSSensitivePathsDetected(t *testing.T) {
	cases := []struct {
		path    string
		keyword string // expected description fragment
	}{
		{"/private/etc/passwd", "passwd"},
		{"/private/etc/master.passwd", "master.passwd"},
		{"/private/etc/hosts", "hosts"},
		{"/private/var/log/system.log", "system.log"},
		{"/private/var/log/asl", "asl"},
		{"/var/log/system.log", "system.log"},
		{"/var/log/install.log", "install.log"},
		{"/Library/Logs/DiagnosticReports", "DiagnosticReports"},
		{"/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist", "airport"},
		{"/Users/Shared", "Shared"},
	}
	for _, tc := range cases {
		findings := Detect(tc.path, "query")
		found := false
		for _, f := range findings {
			if strings.Contains(strings.ToLower(f.Description), strings.ToLower(tc.keyword)) {
				found = true
			}
		}
		if !found {
			t.Fatalf("FAIL: declared macOS sensitive path %q produced %d findings, none matching %q — the trie must cover every declared macosSensitivePaths entry (%+v)", tc.path, len(findings), tc.keyword, findings)
		}
	}
}

// TestDetect_MacOSTraversalPrefixedStillDetected: the traversal-prefixed form
// must carry the sensitive-path classification too — LFI payloads reach the
// sensitive path through ../ prefixes, and pre-fix only the depth crumb fired
// (this is a second defect-case assertion, not a green-both-sides control).
func TestDetect_MacOSTraversalPrefixedStillDetected(t *testing.T) {
	findings := Detect("../../../../private/etc/passwd", "query")
	found := false
	for _, f := range findings {
		if strings.Contains(f.Description, "passwd") {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: harness control — traversal-prefixed /private/etc/passwd must produce the sensitive-path finding, got %+v", findings)
	}
}

// Control: the Linux twin keeps its classification — the fix must not lose
// the existing entries.
func TestDetect_LinuxEtcPasswdStillDetected(t *testing.T) {
	findings := Detect("/etc/passwd", "query")
	found := false
	for _, f := range findings {
		if f.Description == "Access to /etc/passwd detected" {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: harness control — /etc/passwd must keep its trie finding, got %+v", findings)
	}
}

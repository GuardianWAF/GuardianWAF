package lfi

import (
	"regexp"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

var (
	// A Windows administrative share, written with backslashes or after the
	// sanitizer turned them into slashes: \\host\c$\..., //host/c$/...
	uncAdminShare = regexp.MustCompile(`(?:\\\\|//)[^\\/\s]+[\\/](?:[a-z]|admin|ipc|print)\$(?:[\\/]|$)`)
	// A UNC path to the local machine: \\localhost\share, \\127.0.0.1\x, \\::1\x.
	uncLoopback = regexp.MustCompile(`(?:\\\\|//)(?:localhost|127\.\d+\.\d+\.\d+|\[?::1\]?)[\\/]`)
	// Per-user registry hive: holds credentials and recent-file history.
	ntuserHive = regexp.MustCompile(`(?:^|[\\/])ntuser\.dat(?:\.log\d?)?\b`)
)

func checkUNCPaths(lower, location string) []engine.Finding {
	var findings []engine.Finding
	if m := uncMatch(uncAdminShare, lower); m != "" {
		findings = append(findings, makeFinding(70, engine.SeverityHigh,
			"Windows administrative share path detected", m, location, 0.85))
	} else if m := uncMatch(uncLoopback, lower); m != "" {
		findings = append(findings, makeFinding(60, engine.SeverityHigh,
			"UNC path to the local machine detected", m, location, 0.80))
	}
	if m := ntuserHive.FindString(lower); m != "" {
		findings = append(findings, makeFinding(60, engine.SeverityHigh,
			"Windows user registry hive path detected", m, location, 0.80))
	}
	return findings
}

// uncMatch returns the first match of re that begins a path, not one inside a
// URL: the "//" of "https://host/c$/x" follows a colon and is skipped.
func uncMatch(re *regexp.Regexp, s string) string {
	for _, loc := range re.FindAllStringIndex(s, -1) {
		if loc[0] > 0 {
			if p := s[loc[0]-1]; p == ':' || p >= 'a' && p <= 'z' || p >= '0' && p <= '9' {
				continue
			}
		}
		return s[loc[0]:loc[1]]
	}
	return ""
}

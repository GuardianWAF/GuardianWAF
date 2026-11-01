package lfi

import (
	"regexp"
	"strings"

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
	// Each regular expression runs only where its rare literal occurs: an
	// unanchored match over a whole large body costs milliseconds per
	// megabyte. The admin-share form needs a '$', so only a window before
	// each '$' is searched.
	if m := adminShareNear(lower); m != "" {
		findings = append(findings, makeFinding(70, engine.SeverityHigh,
			"Windows administrative share path detected", m, location, 0.85))
	} else if strings.Contains(lower, "localhost") || strings.Contains(lower, "127.") || strings.Contains(lower, "::1") {
		if m := uncMatch(uncLoopback, lower); m != "" {
			findings = append(findings, makeFinding(60, engine.SeverityHigh,
				"UNC path to the local machine detected", m, location, 0.80))
		}
	}
	if strings.Contains(lower, "ntuser") {
		if m := ntuserHive.FindString(lower); m != "" {
			findings = append(findings, makeFinding(60, engine.SeverityHigh,
				"Windows user registry hive path detected", m, location, 0.80))
		}
	}
	return findings
}

// adminShareNear searches a window ahead of each '$' (at most eight) for an
// administrative share path.
func adminShareNear(lower string) string {
	seen := 0
	for from := 0; seen < 8; {
		j := strings.IndexByte(lower[from:], '$')
		if j < 0 {
			return ""
		}
		i := from + j
		from = i + 1
		seen++
		lo := max(0, i-260)
		hi := min(len(lower), i+3)
		if m := uncMatch(uncAdminShare, lower[lo:hi]); m != "" {
			return m
		}
	}
	return ""
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

// isProseAroundPath reports a value that is a sentence with a path in it:
// at least six words, of which at least four are plain letters-only words
// ("C:\Program Files\App\config.ini is where the settings live"). A path
// alone, or a path with a short argument, has none of those.
func isProseAroundPath(lower string) bool {
	// Cookies and form values reach this unrewritten, with '+' for spaces.
	fields := strings.Fields(strings.ReplaceAll(lower, "+", " "))
	if len(fields) < 6 {
		return false
	}
	plain := 0
	for _, f := range fields {
		f = strings.TrimRight(f, ",.!?:;")
		if f == "" {
			continue
		}
		ok := true
		for i := 0; i < len(f); i++ {
			if c := f[i]; !(c >= 'a' && c <= 'z' || c == '\'' || c == '-') {
				ok = false
				break
			}
		}
		if ok {
			plain++
		}
	}
	return plain >= 4
}

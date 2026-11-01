package ssrf

import (
	"regexp"
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

var (
	// Log4Shell and its obfuscations: ${jndi:...}, ${${lower:j}ndi:...},
	// ${${::-j}${::-n}${::-d}${::-i}:...}. Each letter may be a nested lookup.
	jndiLookup = regexp.MustCompile(`\$\{\s*(?:j|\$\{[^}]*\})\s*(?:n|\$\{[^}]*\})\s*(?:d|\$\{[^}]*\})\s*(?:i|\$\{[^}]*\})\s*:`)
	// Out-of-band callback services used by scanners and exploit tooling to
	// learn that a payload ran. Nothing legitimate sends these in a request.
	oastDomain = regexp.MustCompile(`(?:^|[^a-z0-9-])(?:[a-z0-9-]+\.)*(?:burpcollaborator\.net|oastify\.com|oast\.(?:me|fun|live|site|online|pro)|interact\.sh|interactsh\.com|dnslog\.cn|ceye\.io|requestrepo\.com)\b`)
)

// jndiDescription marks findings that must not be halved for the User-Agent
// header: Log4Shell is the best-known payload for exactly that header.
const jndiDescription = "JNDI lookup (Log4Shell)"
const oastDescription = "Out-of-band callback domain"

func checkOutOfBand(lower, location string) []engine.Finding {
	var findings []engine.Finding
	if strings.Contains(lower, "${") {
		if m := jndiLookup.FindString(lower); m != "" {
			findings = append(findings, makeFinding(95, engine.SeverityCritical,
				jndiDescription, m, location, 0.95))
		}
	}
	if strings.Contains(lower, ".") {
		if m := oastDomain.FindString(lower); m != "" {
			findings = append(findings, makeFinding(65, engine.SeverityHigh,
				oastDescription, strings.TrimLeft(m, "^"), location, 0.90))
		}
	}
	return findings
}

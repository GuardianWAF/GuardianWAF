package xxe

import (
	"regexp"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

var (
	// An XML prolog declaring UTF-7: every "<" is written "+ADw-", so a filter
	// that looks for "<!DOCTYPE" sees nothing while a parser that honours the
	// declaration sees the whole payload.
	utf7Prolog = regexp.MustCompile(`<\?xml[^>]*encoding\s*=\s*["']\s*utf-7`)
	// UTF-7 shifted sequences for "<!" and "<?": +ADwAIQ- and +ADwAPw-.
	utf7Markup = regexp.MustCompile(`\+adw(?:aiq|apw)[a-z0-9+/]*-`)
	// An XML Schema include, import or redefine fetching a document by URL:
	// the schema is loaded from the attacker's server.
	schemaFetch = regexp.MustCompile(`<\s*(?:xs|xsd|[a-z]+):(?:include|import|redefine)\b[^>]*\b(?:schemalocation|namespace)\s*=\s*["']\s*(?:https?|ftp|file|gopher|jar)://`)
	// xsi:schemaLocation holds "namespace location" pairs. A single URL with
	// no pair is not valid, and parsers that validate fetch it anyway.
	lonelySchemaLocation = regexp.MustCompile(`\bxsi:(?:nonamespace)?schemalocation\s*=\s*["']\s*(?:https?|ftp|file|gopher|jar)://[^"'\s]+["']`)
)

// checkEncodingEvasion flags XML encoding tricks and external schema fetches.
func checkEncodingEvasion(lower, location string, findings *[]engine.Finding) {
	if m := utf7Prolog.FindString(lower); m != "" {
		*findings = append(*findings, makeFinding(70, engine.SeverityHigh,
			"XML declares UTF-7 encoding (filter evasion)", m, location, 0.85))
	} else if m := utf7Markup.FindString(lower); m != "" {
		*findings = append(*findings, makeFinding(65, engine.SeverityHigh,
			"UTF-7 encoded XML markup (filter evasion)", m, location, 0.80))
	}
	if m := schemaFetch.FindString(lower); m != "" {
		*findings = append(*findings, makeFinding(60, engine.SeverityHigh,
			"XML Schema include/import fetching an external document", m, location, 0.80))
	}
	if m := lonelySchemaLocation.FindString(lower); m != "" {
		*findings = append(*findings, makeFinding(55, engine.SeverityHigh,
			"xsi:schemaLocation with a single external URL (schema fetch)", m, location, 0.75))
	}
}

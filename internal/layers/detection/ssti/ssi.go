package ssti

import (
	"regexp"
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// ssiDirective matches a Server Side Includes directive: <!--#exec cmd="..." -->
// and its siblings. The "<!--#" opener is not valid in ordinary HTML text, so
// a directive name after it is deliberate.
var ssiDirective = regexp.MustCompile(`<!--\s*#\s*(exec|include|echo|config|fsize|flastmod|printenv|set|if|elif|else|endif)\b`)

// checkSSI flags SSI directives. exec runs a command and include reads a file
// or another URL, so both block on their own; the rest disclose environment
// or alter control flow and score lower.
func checkSSI(lower, location string) []engine.Finding {
	m := ssiDirective.FindStringSubmatch(lower)
	if m == nil {
		return nil
	}
	score, severity := 60, engine.SeverityMedium
	switch m[1] {
	case "exec":
		score, severity = 90, engine.SeverityCritical
	case "include":
		score, severity = 80, engine.SeverityHigh
	}
	return []engine.Finding{makeFinding(score, severity,
		"Server Side Includes directive detected", m[0], extractContext(lower, m[0]), location, 0.90)}
}

// checkPolyglotProbe flags the template-engine fuzzing polyglot "${{<%[%'"}}%\":
// it opens the delimiters of several engines at once to make whichever one is
// present throw. Two engine delimiters that never appear together in text are
// the signal.
func checkPolyglotProbe(lower, location string) []engine.Finding {
	if !strings.Contains(lower, "${{") {
		return nil
	}
	if !strings.Contains(lower, "<%") && !strings.Contains(lower, "{%") && !strings.Contains(lower, "#{") {
		return nil
	}
	return []engine.Finding{makeFinding(70, engine.SeverityHigh,
		"Template-engine polyglot probe detected", "${{<%", extractContext(lower, "${{"), location, 0.80)}
}

// Package ssti detects Server-Side Template Injection attempts (Jinja2/Twig,
// Freemarker/Velocity, SpEL/OGNL, ERB, Smarty, etc.) in request inputs.
package ssti

import (
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Detector implements engine.Detector for server-side template injection.
type Detector struct {
	enabled    bool
	multiplier float64
}

// NewDetector creates a new SSTI detector.
func NewDetector(enabled bool, multiplier float64) *Detector {
	return &Detector{enabled: enabled, multiplier: multiplier}
}

// Name returns the layer name.
func (d *Detector) Name() string { return "ssti-detector" }

// Order returns the execution order of this detector (managed by the layer).
func (d *Detector) Order() int { return 0 }

// DetectorName returns the detector identifier.
func (d *Detector) DetectorName() string { return "ssti" }

// Patterns returns the list of attack pattern classes this detector recognizes.
func (d *Detector) Patterns() []string {
	return []string{
		"template-gadget",
		"expression-probe",
		"template-directive",
	}
}

// Process scans the request context for SSTI patterns.
func (d *Detector) Process(ctx *engine.RequestContext) engine.LayerResult {
	if !d.enabled {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	var allFindings []engine.Finding

	// Scan BOTH the raw and the sanitizer-normalized form of every input (the
	// normalizer decodes evasion encodings; the raw form preserves bytes the
	// normalizer may alter). Identical strings are scanned once. Mirrors the other
	// detectors and their fail-open guard for a disabled Sanitizer.
	seen := make(map[string]struct{})
	scan := func(v, location string) {
		if v == "" {
			return
		}
		key := location + "\x00" + v
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		allFindings = append(allFindings, Detect(v, location)...)
	}

	scan(ctx.Path, "path")
	scan(ctx.NormalizedPath, "path")
	for _, values := range ctx.QueryParams {
		for _, v := range values {
			scan(v, "query")
		}
	}
	for _, values := range ctx.NormalizedQuery {
		for _, v := range values {
			scan(v, "query")
		}
	}
	scan(ctx.BodyString, "body")
	scan(ctx.NormalizedBody, "body")
	for _, v := range ctx.Cookies {
		scan(v, "cookie")
	}
	if refs, ok := ctx.Headers["Referer"]; ok {
		for _, v := range refs {
			scan(v, "header")
		}
	}
	if refs, ok := ctx.NormalizedHeaders["Referer"]; ok {
		for _, v := range refs {
			scan(v, "header")
		}
	}

	engine.ApplyMultiplier(allFindings, d.multiplier)

	action := engine.ActionPass
	total := 0
	for _, f := range allFindings {
		total += f.Score
	}
	if total > 0 {
		action = engine.ActionLog
	}
	return engine.LayerResult{Action: action, Findings: allFindings, Score: total}
}

// Detect scans a single input string for SSTI patterns.
func Detect(input, location string) []engine.Finding {
	if input == "" {
		return nil
	}
	lower := strings.ToLower(input)

	var findings []engine.Finding
	findings = append(findings, checkExploitGadgets(lower, location)...)
	findings = append(findings, checkTemplateDirectives(lower, location)...)
	findings = append(findings, checkProbeExpressions(lower, location)...)
	return findings
}

// exploitGadgets are template-injection exploitation primitives that essentially
// never appear in benign traffic — sandbox escapes, RCE gadget chains, and
// engine-internal accessors across the common template engines.
var exploitGadgets = []string{
	// Python / Jinja2 / Tornado / Mako sandbox escape chains
	"__class__",
	"__mro__",
	"__subclasses__",
	"__globals__",
	"__builtins__",
	"__import__",
	"self._templatereference",
	"lipsum.__",
	"cycler.__",
	"joiner.__",
	"request.application.__globals__",
	"os.popen",
	"subprocess",
	"popen(",
	// Java: SpEL / OGNL / Freemarker / Velocity
	"t(java.lang.runtime",
	"t(java.lang.system",
	"java.lang.runtime).getruntime",
	"getruntime().exec",
	"freemarker.template.utility.execute",
	"processbuilder",
	"javax.script",
	"scriptengine",
	// Ruby ERB
	"<%= system",
	"<%=system",
	"io.popen",
	// PHP: Twig / Smarty
	"_self.env",
	"registerundefinedfiltercallback",
	"{php}",
	"{system(",
}

func checkExploitGadgets(lower, location string) []engine.Finding {
	var findings []engine.Finding
	for _, g := range exploitGadgets {
		if strings.Contains(lower, g) {
			findings = append(findings, makeFinding(85, engine.SeverityCritical,
				"SSTI exploitation gadget detected", g, extractContext(lower, g), location, 0.90))
		}
	}
	return findings
}

// templateDirectives are dangerous template control directives.
var templateDirectives = []string{
	"{% import",
	"{%import",
	"{% include",
	"<#assign",
	"#set($",
	"${@",  // OGNL/SpEL static access
	"#{t(", // SpEL type reference
	"*{t(", // Thymeleaf SpEL
}

func checkTemplateDirectives(lower, location string) []engine.Finding {
	var findings []engine.Finding
	for _, dctv := range templateDirectives {
		if strings.Contains(lower, dctv) {
			findings = append(findings, makeFinding(70, engine.SeverityHigh,
				"Dangerous template directive detected", dctv, extractContext(lower, dctv), location, 0.80))
		}
	}
	return findings
}

// delimiters are the opening tokens of template expressions across engines.
var delimiters = []string{"{{", "${", "#{", "<%=", "*{", "~{"}

// checkProbeExpressions detects the canonical SSTI detection probe: a template
// expression wrapping a numeric-literal multiplication (e.g. {{7*7}}, ${7*7},
// #{7*7}, <%= 7*7 %>). Requiring numeric literals (not variables) keeps benign
// templates like {{price * qty}} from matching.
func checkProbeExpressions(lower, location string) []engine.Finding {
	for _, open := range delimiters {
		from := 0
		for {
			i := strings.Index(lower[from:], open)
			if i < 0 {
				break
			}
			start := from + i + len(open)
			// Bound the expression body so we don't scan unrelated text.
			end := start + 64
			if end > len(lower) {
				end = len(lower)
			}
			if hasLiteralMultiplication(lower[start:end]) {
				return []engine.Finding{makeFinding(50, engine.SeverityMedium,
					"SSTI expression-evaluation probe detected", open,
					extractContext(lower, open), location, 0.65)}
			}
			from = start
		}
	}
	return nil
}

// hasLiteralMultiplication reports whether s contains a numeric literal followed
// by '*' followed by a numeric literal (optionally quoted), ignoring spaces —
// the signature of SSTI probes like 7*7 or 7*'7'.
func hasLiteralMultiplication(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '*' {
			continue
		}
		// left of '*': a digit, after optional spaces
		l := i - 1
		for l >= 0 && s[l] == ' ' {
			l--
		}
		if l < 0 || s[l] < '0' || s[l] > '9' {
			continue
		}
		// right of '*': a digit or quote+digit, after optional spaces
		r := i + 1
		for r < len(s) && s[r] == ' ' {
			r++
		}
		if r < len(s) && (s[r] == '\'' || s[r] == '"') {
			r++
		}
		if r < len(s) && s[r] >= '0' && s[r] <= '9' {
			return true
		}
	}
	return false
}

func makeFinding(score int, severity engine.Severity, desc, matched, context, location string, confidence float64) engine.Finding {
	if matched == "" {
		matched = context
	}
	if len(matched) > 200 {
		matched = matched[:197] + "..."
	}
	return engine.Finding{
		DetectorName: "ssti",
		Category:     "ssti",
		Severity:     severity,
		Score:        score,
		Description:  desc,
		MatchedValue: matched,
		Location:     location,
		Confidence:   confidence,
	}
}

func extractContext(input, pattern string) string {
	idx := strings.Index(input, pattern)
	if idx < 0 {
		if len(input) > 100 {
			return input[:100]
		}
		return input
	}
	start := max(idx-20, 0)
	end := min(idx+len(pattern)+20, len(input))
	result := input[start:end]
	if len(result) > 200 {
		result = result[:197] + "..."
	}
	return result
}

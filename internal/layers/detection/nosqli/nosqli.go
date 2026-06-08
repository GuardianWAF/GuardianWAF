// Package nosqli detects NoSQL injection attempts — MongoDB-style operator
// injection (query-string and JSON), authentication-bypass payloads, and
// server-side JavaScript execution ($where/$function/$accumulator).
package nosqli

import (
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Detector implements engine.Detector for NoSQL injection.
type Detector struct {
	enabled    bool
	multiplier float64
}

// NewDetector creates a new NoSQL injection detector.
func NewDetector(enabled bool, multiplier float64) *Detector {
	return &Detector{enabled: enabled, multiplier: multiplier}
}

// Name returns the layer name.
func (d *Detector) Name() string { return "nosqli-detector" }

// Order returns the execution order of this detector (managed by the layer).
func (d *Detector) Order() int { return 0 }

// DetectorName returns the detector identifier.
func (d *Detector) DetectorName() string { return "nosqli" }

// Patterns returns the attack pattern classes this detector recognizes.
func (d *Detector) Patterns() []string {
	return []string{
		"server-side-js",
		"operator-injection",
		"auth-bypass",
	}
}

// Process scans the request context for NoSQL injection patterns.
func (d *Detector) Process(ctx *engine.RequestContext) engine.LayerResult {
	if !d.enabled {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	var allFindings []engine.Finding

	// Scan BOTH the raw and the sanitizer-normalized form of every input
	// (deduped). Mirrors the other detectors and their disabled-Sanitizer guard.
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
	for k, values := range ctx.QueryParams {
		// Bracket operator injection (user[$ne]=) lives in the parameter NAME,
		// so scan keys as well as values.
		scan(k, "query")
		for _, v := range values {
			scan(v, "query")
		}
	}
	for k, values := range ctx.NormalizedQuery {
		scan(k, "query")
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

// Detect scans a single input string for NoSQL injection patterns.
func Detect(input, location string) []engine.Finding {
	if input == "" {
		return nil
	}
	lower := strings.ToLower(input)

	var findings []engine.Finding
	findings = append(findings, checkServerSideJS(lower, location)...)
	findings = append(findings, checkBracketOperators(lower, location)...)
	findings = append(findings, checkAuthBypass(lower, location)...)
	findings = append(findings, checkInjectionOperators(lower, location)...)
	return findings
}

// serverSideJS are MongoDB server-side JavaScript-execution operators (RCE/DoS).
var serverSideJS = []string{"$where", "$function", "$accumulator", "mapreduce"}

func checkServerSideJS(lower, location string) []engine.Finding {
	var findings []engine.Finding
	for _, op := range serverSideJS {
		if strings.Contains(lower, op) {
			findings = append(findings, makeFinding(90, engine.SeverityCritical,
				"NoSQL server-side JavaScript operator detected", op, location, 0.90))
		}
	}
	return findings
}

// bracketOperators are MongoDB operators injected via query-string object syntax
// (e.g. username[$ne]=). The bracket form is unambiguous injection.
var bracketOperators = []string{
	"[$ne]", "[$eq]", "[$gt]", "[$gte]", "[$lt]", "[$lte]", "[$in]", "[$nin]",
	"[$regex]", "[$exists]", "[$or]", "[$and]", "[$not]", "[$where]", "[$elemmatch]",
}

func checkBracketOperators(lower, location string) []engine.Finding {
	var findings []engine.Finding
	for _, op := range bracketOperators {
		if strings.Contains(lower, op) {
			findings = append(findings, makeFinding(75, engine.SeverityHigh,
				"NoSQL operator injection via query-string object syntax", op, location, 0.88))
			break // one bracket finding is enough to block; avoid score pile-up
		}
	}
	return findings
}

// bypassOperators are comparison operators (NOT the array operators $in/$nin,
// which are common in legitimate filter APIs). Paired with a null/empty/boolean
// value they form the classic auth-bypass payload.
var bypassOperators = []string{"$ne", "$gt", "$gte", "$lt", "$lte", "$eq"}

func checkAuthBypass(lower, location string) []engine.Finding {
	for _, op := range bypassOperators {
		idx := 0
		for {
			i := strings.Index(lower[idx:], op)
			if i < 0 {
				break
			}
			pos := idx + i + len(op)
			// Skip a closing key quote and spaces, then require ':' and a
			// bypass-y value (null / "" / '' / true / false). Arrays/numbers are
			// excluded so legitimate filters like {"$gt":100} do not match.
			rest := strings.TrimLeft(lower[pos:], "\" ")
			if strings.HasPrefix(rest, ":") {
				val := strings.TrimLeft(rest[1:], " ")
				if strings.HasPrefix(val, "null") || strings.HasPrefix(val, `""`) ||
					strings.HasPrefix(val, "''") || strings.HasPrefix(val, "true") ||
					strings.HasPrefix(val, "false") {
					return []engine.Finding{makeFinding(70, engine.SeverityHigh,
						"NoSQL authentication-bypass operator detected", op, location, 0.85)}
				}
			}
			idx = pos
		}
	}
	return nil
}

// injectionOperators are operators that, in user input, indicate injection but
// also occasionally appear in legitimate filter APIs — scored to log/contribute
// rather than block on their own.
var injectionOperators = []string{"\"$regex\"", "\"$expr\"", "\"$jsonschema\"", "\"$text\"", "\"$mod\""}

func checkInjectionOperators(lower, location string) []engine.Finding {
	var findings []engine.Finding
	for _, op := range injectionOperators {
		if strings.Contains(lower, op) {
			findings = append(findings, makeFinding(40, engine.SeverityMedium,
				"NoSQL query operator in user input", strings.Trim(op, "\""), location, 0.60))
			break
		}
	}
	return findings
}

func makeFinding(score int, severity engine.Severity, desc, matched, location string, confidence float64) engine.Finding {
	if len(matched) > 200 {
		matched = matched[:197] + "..."
	}
	return engine.Finding{
		DetectorName: "nosqli",
		Category:     "nosqli",
		Severity:     severity,
		Score:        score,
		Description:  desc,
		MatchedValue: matched,
		Location:     location,
		Confidence:   confidence,
	}
}

// Package ldapi detects LDAP filter injection: input that closes the filter
// the application built and appends its own boolean clauses, or that smuggles
// in an extensible-match assertion.
package ldapi

import (
	"regexp"
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Detector implements engine.Detector for LDAP injection.
type Detector struct {
	enabled    bool
	multiplier float64
}

// NewDetector creates a new LDAP injection detector.
func NewDetector(enabled bool, multiplier float64) *Detector {
	return &Detector{enabled: enabled, multiplier: multiplier}
}

// Name returns the layer name.
func (d *Detector) Name() string { return "ldapi-detector" }

// Order returns the execution order of this detector (managed by the layer).
func (d *Detector) Order() int { return 0 }

// DetectorName returns the detector identifier.
func (d *Detector) DetectorName() string { return "ldapi" }

// Patterns returns the attack pattern classes this detector recognizes.
func (d *Detector) Patterns() []string {
	return []string{
		"filter-clause-injection",
		"boolean-filter",
		"extensible-match",
		"wildcard-bypass",
	}
}

// Process scans the request context for LDAP injection.
func (d *Detector) Process(ctx *engine.RequestContext) engine.LayerResult {
	if !d.enabled {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	var allFindings []engine.Finding
	seen := make(map[[2]string]struct{})
	scan := func(v, location string) {
		if v == "" {
			return
		}
		key := [2]string{location, v}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		allFindings = append(allFindings, Detect(v, location)...)
	}

	scan(ctx.Path, "path")
	scan(ctx.NormalizedPath, "path")
	for k, values := range ctx.QueryParams {
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
	for _, v := range ctx.BodyViews() {
		scan(v, "body")
	}
	for _, v := range ctx.CookieViews() {
		scan(v, "cookie")
	}
	for _, name := range []string{"User-Agent", "Referer"} {
		for _, v := range ctx.Headers[name] {
			scan(v, "header")
		}
		for _, v := range ctx.NormalizedHeaders[name] {
			scan(v, "header")
		}
	}
	for _, v := range ctx.CustomHeaderViews() {
		scan(v, "header")
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

// maxScan bounds the work per value.
const maxScan = 16 << 10

var (
	// A boolean operator opening a clause that holds an attribute assertion:
	// (&(uid=admin)...  (|(cn=*)...  (!(objectclass=x)...
	booleanClause = regexp.MustCompile(`\(\s*[&|!]\s*\(\s*[A-Za-z][A-Za-z0-9.-]*\s*(?:[=<>~]|:[^)]*=)`)
	// A closed clause followed at once by a new clause with an assertion:
	// admin)(uid=*   *)(objectclass=*   x)(|(a=b
	clauseBreak = regexp.MustCompile(`\)\([&|!]?[A-Za-z][A-Za-z0-9.-]*[=<>~]`)
	// The absolute true / false filters (&) and (|) closing an injected clause.
	absoluteFilter = regexp.MustCompile(`\)\([&|]\)`)
	// Extensible match: attr:oid:=value, attr:dn:=, attr:caseExactMatch:=value.
	extensible = regexp.MustCompile(`(?i)\b[A-Za-z][A-Za-z0-9-]*:(?:dn:)?(?:\d+(?:\.\d+){2,}|[a-z]+match|dn):=`)
	// A wildcard-only or present-assertion clause: (objectclass=*) (uid=*)
	presence = regexp.MustCompile(`(?i)\(\s*(?:objectclass|uid|cn|sn|mail|samaccountname|userprincipalname|memberof|userpassword)\s*=\s*\*\s*\)`)
	// A value that is only a wildcard run followed by a clause end.
	wildcardClose = regexp.MustCompile(`^\*+\)`)
)

// Detect scans a single input for LDAP injection.
func Detect(input, location string) []engine.Finding {
	if len(input) > maxScan {
		input = input[:maxScan]
	}
	if !strings.Contains(input, ")") && !strings.Contains(input, "(") && !strings.Contains(input, ":=") {
		return nil
	}
	var findings []engine.Finding
	add := func(score int, sev engine.Severity, desc, matched string) {
		findings = append(findings, makeFinding(score, sev, desc, matched, location, 0.85))
	}

	if m := booleanClause.FindString(input); m != "" {
		add(65, engine.SeverityHigh, "LDAP filter injection: boolean clause with attribute assertion", m)
	}
	if m := clauseBreak.FindString(input); m != "" {
		// A clause break next to a presence test or wildcard is what a
		// filter bypass looks like; on its own it still opens a new clause.
		score := 50
		if presence.MatchString(input) || strings.Contains(input, "*)") {
			score = 65
		}
		add(score, engine.SeverityHigh, "LDAP filter injection: filter clause closed and a new one opened", m)
	}
	if m := absoluteFilter.FindString(input); m != "" {
		add(60, engine.SeverityHigh, "LDAP filter injection: absolute true/false filter", m)
	}
	if m := extensible.FindString(input); m != "" {
		add(65, engine.SeverityHigh, "LDAP filter injection: extensible match assertion", m)
	}
	if m := presence.FindString(input); m != "" && len(findings) == 0 {
		add(55, engine.SeverityMedium, "LDAP filter injection: wildcard presence clause", m)
	}
	if len(findings) == 0 && wildcardClose.MatchString(strings.TrimSpace(input)) {
		add(40, engine.SeverityLow, "LDAP filter injection: wildcard closing a filter", input)
	}
	return findings
}

func makeFinding(score int, severity engine.Severity, desc, matched, location string, confidence float64) engine.Finding {
	if len(matched) > 200 {
		matched = matched[:197] + "..."
	}
	return engine.Finding{
		DetectorName: "ldapi",
		Category:     "ldapi",
		Severity:     severity,
		Score:        score,
		Description:  desc,
		MatchedValue: matched,
		Location:     location,
		Confidence:   confidence,
	}
}

package nosqli

import (
	"regexp"
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

var (
	// An unquoted logical operator opening an array: ", $or: [" or "{$and:[".
	// Legitimate filter APIs send the key quoted ("$or": [...]); an unquoted
	// key is what input breaking out of a string into an object literal looks
	// like.
	bareLogicalOperator = regexp.MustCompile(`[,{(]\s*\$(?:or|and|nor)\s*:\s*\[`)
	// An empty clause as the first element of $or/$nor/$and: always true, so
	// it matches every document. A real filter never lists an empty clause.
	emptyClause = regexp.MustCompile(`\$(?:or|nor)["']?\s*:\s*\[\s*\{\s*\}`)
	// A time-based busy loop in server-side JavaScript: the DoS payload of
	// $where / mapReduce / eval injection.
	busyLoop = regexp.MustCompile(`\b(?:do\s*\{[^}]*\}\s*while|while)\s*\([^)]*(?:date|now|time)`)
	// JavaScript statements after a quote that closed a string: the payload
	// shape of $where, mapReduce and eval injection ("'; return true; var x='").
	jsAfterQuote = regexp.MustCompile(`['"]\s*;\s*(?:return\s+(?:true|false|null|this\b|!|[01]\s*;)|var\s+\w+\s*=|let\s+\w+\s*=|const\s+\w+\s*=|function\s*\w*\s*\(|while\s*\(\s*(?:true|1)\s*\)|for\s*\(\s*;)`)
	// Mongo shell commands that change data or schema.
	shellMutation = regexp.MustCompile(`\bdb\.(?:[a-z0-9_]+\.(?:insert|insertone|insertmany|update|updateone|updatemany|replaceone|remove|deleteone|deletemany|drop|save|findandmodify|findoneanddelete|findoneandupdate|bulkwrite)|dropdatabase|createuser|dropuser|runcommand|eval|copydatabase|getsiblingdb)\s*\(`)
	// Prototype pollution: __proto__ used as a key or an index, or reached
	// through constructor.prototype.
	prototypePollution = regexp.MustCompile(`__proto__\s*(?:\[|=|["']\s*\]|["']\s*:)|constructor\s*(?:\.\s*prototype|\[\s*["']?prototype["']?\s*\])\s*(?:\.|\[|=)`)
)

// checkJSInjection finds server-side JavaScript and object-injection payloads
// that do not use a $-prefixed key.
func checkJSInjection(lower, location string) []engine.Finding {
	var findings []engine.Finding
	if m := bareLogicalOperator.FindString(lower); m != "" {
		findings = append(findings, makeFinding(70, engine.SeverityHigh,
			"NoSQL logical operator injected into an object literal", strings.TrimSpace(m), location, 0.85))
	}
	if strings.Contains(lower, "$") {
		if m := emptyClause.FindString(lower); m != "" {
			findings = append(findings, makeFinding(60, engine.SeverityHigh,
				"NoSQL always-true clause: empty object in $or", m, location, 0.80))
		}
	}
	if strings.Contains(lower, "while") && (strings.Contains(lower, "date") || strings.Contains(lower, "now") || strings.Contains(lower, "time")) {
		if m := busyLoop.FindString(lower); m != "" && (strings.Contains(lower, "new date") || strings.Contains(lower, "date.now") || strings.Contains(lower, "new date()")) {
			findings = append(findings, makeFinding(85, engine.SeverityCritical,
				"Server-side JavaScript busy loop (time-based DoS)", m, location, 0.90))
		}
	}
	if strings.Contains(lower, "db.") {
		if m := shellMutation.FindString(lower); m != "" {
			findings = append(findings, makeFinding(60, engine.SeverityHigh,
				"Mongo shell data-changing command in user input", m, location, 0.80))
		}
	}
	if strings.Contains(lower, ";") {
		if m := jsAfterQuote.FindString(lower); m != "" {
			findings = append(findings, makeFinding(70, engine.SeverityHigh,
				"JavaScript statements after a closed string (server-side JS injection)", m, location, 0.80))
		}
	}
	if strings.Contains(lower, "__proto__") || strings.Contains(lower, "constructor") {
		if m := prototypePollution.FindString(lower); m != "" {
			findings = append(findings, makeFinding(75, engine.SeverityHigh,
				"Prototype pollution attempt", m, location, 0.85))
		}
	}
	return findings
}

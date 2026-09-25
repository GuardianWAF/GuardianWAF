package crs

// FuzzCrsParse exercises the CRS SecRule text parser (ParseFile →
// parseSecRule/parseSecAction → parseVariables/parseOperator/parseActions →
// splitQuoted/splitEscaped/splitActions) against hostile directive text.
// The layer must never panic, returned rules must be non-nil, and the
// LoadError contract must hold: a parse error yields nil rules (serve
// refuses to start on loadErr — no partial rulesets).

import (
	"testing"
)

func FuzzCrsParse(f *testing.F) {
	seeds := []string{
		``,
		"# comment only\n",
		"SecRuleEngine On\n",
		`SecRule REQUEST_URI "@contains /" "id:1,deny"`,
		"SecRule ARGS \"@rx attack\" \"id:2,chain\"\n\tSecRule REQUEST_METHOD \"@streq POST\" \"id:3\"",
		`SecAction "id:4,phase:1,pass"`,
		`SecRule ARGS "@validateByteRange 1-255" "id:5,msg:\"a, b\",deny"`,
		`SecRule REQUEST_URI "@pmf /etc/hosts" "id:6"`,
		"SecRule &ARGS \"@ge 10\" \"id:7,chain\"\nSecAction \"id:8\"",
		`SecRule `,
		`SecRule X`,
		`SecRule X "@rx"`,
		`SecRule X "@rx" "malformed`,
		"SecRuleUpdateTargetById 1 ARGS\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, content string) {
		if len(content) > 8192 {
			return
		}
		p := NewParser()
		rules, err := p.ParseFile(content)

		// LoadError contract: a parse error must yield nil rules — serve
		// refuses to start on loadErr, so a partial ruleset returned with
		// an error would be a silent-truncation hazard.
		if err != nil && rules != nil {
			t.Fatalf("FAIL: parse error returned with non-nil rules (len=%d): %v", len(rules), err)
		}
		for _, r := range rules {
			if r == nil {
				t.Fatalf("FAIL: nil rule in parsed ruleset")
			}
		}
	})
}

// Regression (round 2026-09-25-round15-crs-parser-fuzz): the quote-strip
// guards satisfied a 1-byte string of just a quote character (HasPrefix AND
// HasSuffix are both true for it), slicing [1:0] and panicking rule loading
// — a malformed CRS ruleset line crashed the WAF at startup/reload instead
// of producing the designed LoadError. All three strip sites (SecRule
// actions, SecAction content, parseActions action value in both quote
// variants) are length-guarded now; lone-quote directives flow through the
// normal error path. The fuzz corpus entry 2b507a2b48ffd553 pins the
// SecRule variant; this test pins all three sites deterministically.
func TestCrsQuoteStripNoPanicOnLoneQuote(t *testing.T) {
	inputs := []string{
		`SecRule 0 0 "`,               // site 1: SecRule actions strip
		`SecAction "`,                 // site 2: SecAction content strip
		`SecRule ARGS "@rx" "msg:'"`,  // site 3: action value strip, single quote
		`SecRule ARGS "@rx" "msg:\""`, // site 3: action value strip, double quote
	}
	for _, in := range inputs {
		p := NewParser()
		_, _ = p.ParseFile(in) // must not panic; error or success both fine
	}
}

// Regression (round 2026-09-25-round16-crs-layer-process-fuzz): parseVariables'
// key-regex strip had the same unguarded [1:len-1] idiom as the round-15
// quote strips — a lone-slash key (from a variable spec like 0:/ or ARGS:/)
// is its own prefix and suffix and panicked rule loading. Found by
// FuzzCrsLayerProcess corpus 25bc1eddba66e639.
func TestCrsKeyRegexStripNoPanicOnLoneSlash(t *testing.T) {
	p := NewParser()
	_, _ = p.ParseFile("SecRule 0:/ 0 0")             // must not panic
	_, _ = p.ParseFile(`SecRule ARGS:/ "@rx" "id:1"`) // must not panic
}

package xss

import (
	"regexp"
	"strings"
)

var (
	// A sink reached without a plain call: alert.call(null,1), alert.apply(),
	// alert?.(1). They run the same code as alert(1) and slip past a matcher
	// that wants the name followed by '('.
	indirectSinkCall = regexp.MustCompile("\\b(?:alert|confirm|prompt|eval|settimeout|setinterval|execscript)\\s*(?:\\.\\s*(?:call|apply|bind)\\s*\\(|\\?\\.\\s*\\()")
	// A parenthesised sink called at once: (alert)(1), (eval)('...').
	parenSinkCall = regexp.MustCompile(`\(\s*(?:alert|confirm|prompt|eval)\s*\)\s*\(`)
	// A sink handed a browser object: alert(document.domain), prompt(window.name).
	sinkWithBrowserArg = regexp.MustCompile(`\b(?:alert|confirm|prompt)\s*\(\s*(?:document|window|self|top|parent)\s*(?:\.|\[|\?\.)`)
	// document["cookie"], document?.cookie, window['eval']: bracket and
	// optional-chaining access to the same properties.
	bracketAccess = regexp.MustCompile("\\bdocument\\s*(?:\\?\\.\\s*cookie\\b|\\[\\s*[\"'`]cookie[\"'`]\\s*\\])|\\b(?:window|self|top|globalthis|this)\\s*\\[\\s*[\"'`](?:alert|eval|confirm|prompt|location|document)[\"'`]\\s*\\]")
	// ".constructor('code')()": the Function constructor, as in template
	// engine gadgets such as _c.constructor('alert(1)')().
	functionConstructor = regexp.MustCompile("\\.\\s*constructor\\s*\\(\\s*[\"'`][^\"'`]*[\"'`]\\s*\\)\\s*\\(")
	// Code after "javascript:" separated by a space: an identifier then a call
	// or assignment, or an opening bracket/operator. "JavaScript: Basics of
	// JavaScript" is a title, not a URL.
	codeAfterScheme = regexp.MustCompile("^(?:[a-z_$][\\w$.]*[(=`\\[]|[({!~+;-])")
)

// indirectSinkFindings returns a description for each indirect-sink form in
// the input, in the form checkSinks reports them.
func indirectSinkFindings(lower string) []string {
	var out []string
	if !strings.ContainsAny(lower, "(.[") {
		return nil
	}
	if indirectSinkCall.MatchString(lower) {
		out = append(out, "Dangerous JS sink called through call/apply/optional chaining")
	}
	if parenSinkCall.MatchString(lower) {
		out = append(out, "Parenthesised dangerous JS sink call")
	}
	if sinkWithBrowserArg.MatchString(lower) {
		out = append(out, "Dialog sink handed a browser object")
	}
	if bracketAccess.MatchString(lower) {
		out = append(out, "Bracket or optional-chaining access to a browser sink")
	}
	if functionConstructor.MatchString(lower) {
		out = append(out, "Function constructor call (constructor('code')())")
	}
	return out
}

// jsProtocolIsCode reports a "javascript:" in lower that a browser would run:
// at the end of the value, directly followed by code, or followed by a space
// and then code-shaped text. Prose such as "JavaScript: Basics of JavaScript"
// has a space and then words, and is ignored.
func jsProtocolIsCode(lower string) bool {
	const scheme = "javascript:"
	for from := 0; ; {
		i := strings.Index(lower[from:], scheme)
		if i < 0 {
			return false
		}
		rest := lower[from+i+len(scheme):]
		from += i + len(scheme)
		// '+' is a space in form-encoded values and cookies that were not decoded.
		if rest == "" || (rest[0] != ' ' && rest[0] != '\t' && rest[0] != '+') {
			return true
		}
		trimmed := strings.TrimLeft(rest, " \t+")
		if trimmed == "" || codeAfterScheme.MatchString(trimmed) {
			return true
		}
	}
}

// squeezeJunkTags removes the one- and two-letter pseudo tags an attacker
// threads through a keyword ("o<x>nfocus=alert<x>(1)") that a sanitizer
// strips on the way to the page, leaving "onfocus=alert(1)". It reports
// whether anything was removed.
func squeezeJunkTags(s string) (string, bool) {
	if strings.IndexByte(s, '<') < 0 {
		return s, false
	}
	var b strings.Builder
	changed := false
	for i := 0; i < len(s); i++ {
		if s[i] == '<' {
			j := i + 1
			for j < len(s) && j-i <= 3 && (s[j] >= 'a' && s[j] <= 'z' || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			if j < len(s) && s[j] == '>' && j-i >= 2 && i > 0 && isWordByte(s[i-1]) {
				i = j
				changed = true
				continue
			}
		}
		b.WriteByte(s[i])
	}
	if !changed {
		return s, false
	}
	return b.String(), true
}

func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '(' || c == '=' || c == '_'
}

package xss

import (
	"regexp"
	"strings"
)

// codeAfterScheme matches code after "javascript:" separated by a space: an
// identifier then a call or assignment, or an opening bracket/operator.
// "JavaScript: Basics of JavaScript" is a title, not a URL.
var codeAfterScheme = regexp.MustCompile("^(?:[a-z_$][\\w$.]*[(=`\\[]|[({!~+;-])")

// sinkNames are the functions whose invocation runs attacker code or shows
// the proof-of-concept dialog.
var sinkNames = []string{"alert", "confirm", "prompt", "eval", "settimeout", "setinterval", "execscript"}

var dialogSinks = []string{"alert", "confirm", "prompt"}

var browserObjects = []string{"document", "window", "self", "top", "parent"}

// The checks below scan for a rare anchor ("call", "constructor", a sink name)
// and look only at the text around it. A regular expression over the whole
// input costs several milliseconds per megabyte on every large body.

func isIdentByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '$'
}

func skipSpaces(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	return i
}

// identBefore returns the identifier that ends at s[:end], ignoring spaces
// between it and end.
func identBefore(s string, end int) string {
	for end > 0 && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	start := end
	for start > 0 && isIdentByte(s[start-1]) {
		start--
	}
	return s[start:end]
}

// wordAt reports whether name occurs at s[i:] as a whole word.
func wordAt(s string, i int, name string) bool {
	if !strings.HasPrefix(s[i:], name) {
		return false
	}
	if i > 0 && isIdentByte(s[i-1]) {
		return false
	}
	end := i + len(name)
	return end >= len(s) || !isIdentByte(s[end])
}

func isSink(name string) bool {
	for _, n := range sinkNames {
		if name == n {
			return true
		}
	}
	return false
}

// eachWord calls f with the index of every whole-word occurrence of name until
// f returns true, and reports whether it did.
func eachWord(s, name string, f func(i int) bool) bool {
	for from := 0; from < len(s); {
		j := strings.Index(s[from:], name)
		if j < 0 {
			return false
		}
		i := from + j
		if wordAt(s, i, name) && f(i) {
			return true
		}
		from = i + len(name)
	}
	return false
}

// indirectSinkCall: alert.call(null,1), alert.apply(), alert?.(1). They run the
// same code as alert(1) and slip past a matcher that wants the name followed
// by '('.
func indirectSinkCall(s string) bool {
	for _, anchor := range []string{".call", ".apply", ".bind"} {
		for from := 0; ; {
			j := strings.Index(s[from:], anchor)
			if j < 0 {
				break
			}
			i := from + j
			from = i + len(anchor)
			if isSink(identBefore(s, i)) {
				if k := skipSpaces(s, i+len(anchor)); k < len(s) && s[k] == '(' {
					return true
				}
			}
		}
	}
	for from := 0; ; {
		j := strings.Index(s[from:], "?.")
		if j < 0 {
			return false
		}
		i := from + j
		from = i + 2
		if isSink(identBefore(s, i)) {
			if k := skipSpaces(s, i+2); k < len(s) && s[k] == '(' {
				return true
			}
		}
	}
}

// parenSinkCall: (alert)(1), (eval)('...').
func parenSinkCall(s string) bool {
	for _, name := range []string{"alert", "confirm", "prompt", "eval"} {
		if eachWord(s, name, func(i int) bool {
			l := i
			for l > 0 && (s[l-1] == ' ' || s[l-1] == '\t') {
				l--
			}
			if l == 0 || s[l-1] != '(' {
				return false
			}
			k := skipSpaces(s, i+len(name))
			if k >= len(s) || s[k] != ')' {
				return false
			}
			k = skipSpaces(s, k+1)
			return k < len(s) && s[k] == '('
		}) {
			return true
		}
	}
	return false
}

// sinkWithBrowserArg: alert(document.domain), prompt(window.name).
func sinkWithBrowserArg(s string) bool {
	for _, name := range dialogSinks {
		if eachWord(s, name, func(i int) bool {
			k := skipSpaces(s, i+len(name))
			if k >= len(s) || s[k] != '(' {
				return false
			}
			k = skipSpaces(s, k+1)
			for _, obj := range browserObjects {
				if !strings.HasPrefix(s[k:], obj) {
					continue
				}
				e := skipSpaces(s, k+len(obj))
				if e < len(s) && (s[e] == '.' || s[e] == '[' || strings.HasPrefix(s[e:], "?.")) {
					return true
				}
			}
			return false
		}) {
			return true
		}
	}
	return false
}

// quotedName reads ["name"], ['name'] or [`name`] at s[i:], returning the name
// and the index after the closing bracket.
func quotedName(s string, i int) (string, int, bool) {
	i = skipSpaces(s, i)
	if i >= len(s) || s[i] != '[' {
		return "", 0, false
	}
	i = skipSpaces(s, i+1)
	if i >= len(s) || (s[i] != '"' && s[i] != '\'' && s[i] != '`') {
		return "", 0, false
	}
	q := s[i]
	end := strings.IndexByte(s[i+1:], q)
	if end < 0 || end > 32 {
		return "", 0, false
	}
	name := s[i+1 : i+1+end]
	j := skipSpaces(s, i+1+end+1)
	if j >= len(s) || s[j] != ']' {
		return "", 0, false
	}
	return name, j + 1, true
}

// bracketAccess: document["cookie"], document?.cookie, window['eval'].
func bracketAccess(s string) bool {
	if eachWord(s, "document", func(i int) bool {
		k := skipSpaces(s, i+len("document"))
		if strings.HasPrefix(s[k:], "?.") {
			k = skipSpaces(s, k+2)
			return wordAt(s, k, "cookie")
		}
		name, _, ok := quotedName(s, k)
		return ok && name == "cookie"
	}) {
		return true
	}
	for _, obj := range []string{"window", "self", "top", "globalthis", "this"} {
		if eachWord(s, obj, func(i int) bool {
			name, _, ok := quotedName(s, i+len(obj))
			if !ok {
				return false
			}
			switch name {
			case "alert", "eval", "confirm", "prompt", "location", "document":
				return true
			}
			return false
		}) {
			return true
		}
	}
	return false
}

// functionConstructor: ".constructor('code')()", the Function constructor as
// in template-engine gadgets such as _c.constructor('alert(1)')().
func functionConstructor(s string) bool {
	return eachWord(s, "constructor", func(i int) bool {
		l := i
		for l > 0 && (s[l-1] == ' ' || s[l-1] == '\t') {
			l--
		}
		if l == 0 || s[l-1] != '.' {
			return false
		}
		k := skipSpaces(s, i+len("constructor"))
		if k >= len(s) || s[k] != '(' {
			return false
		}
		k = skipSpaces(s, k+1)
		if k >= len(s) || (s[k] != '"' && s[k] != '\'' && s[k] != '`') {
			return false
		}
		end := strings.IndexByte(s[k+1:], s[k])
		if end < 0 || end > 400 {
			return false
		}
		k = skipSpaces(s, k+1+end+1)
		if k >= len(s) || s[k] != ')' {
			return false
		}
		k = skipSpaces(s, k+1)
		return k < len(s) && s[k] == '('
	})
}

// indirectSinkFindings returns a description for each indirect-sink form in
// the input, in the form checkSinks reports them.
func indirectSinkFindings(lower string) []string {
	var out []string
	if !strings.ContainsAny(lower, "(.[") {
		return nil
	}
	if indirectSinkCall(lower) {
		out = append(out, "Dangerous JS sink called through call/apply/optional chaining")
	}
	if parenSinkCall(lower) {
		out = append(out, "Parenthesised dangerous JS sink call")
	}
	if sinkWithBrowserArg(lower) {
		out = append(out, "Dialog sink handed a browser object")
	}
	if bracketAccess(lower) {
		out = append(out, "Bracket or optional-chaining access to a browser sink")
	}
	if functionConstructor(lower) {
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

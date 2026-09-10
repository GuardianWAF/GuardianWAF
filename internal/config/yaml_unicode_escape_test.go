package config

import "testing"

// Regression: unescapeDoubleQuoted implemented none of the YAML 1.2 §5.7
// unicode escape sequences — \xXX, \uXXXX and \UXXXXXXXX were stored as the
// literal backslash sequence ("caf\u00e9" loaded as c,a,f,\,u,0,0,e,9). Any
// config value written by standard YAML/JSON tooling (which emits \uXXXX for
// non-ASCII and control characters) was silently corrupted. The escapes now
// decode to their code points, surrogate pairs combine, malformed sequences
// stay literal, and single-quoted strings remain escape-free.
func TestYAMLUnicodeEscapesDecode(t *testing.T) {
	cases := []struct {
		name string
		in   string
		key  string
		want string
	}{
		{"hex \\uXXXX decodes (non-ASCII)", `k: "caf\u00e9"`, "k", "café"},
		{"adjacent \\uXXXX decode (ASCII)", `k: "\u0041\u0042"`, "k", "AB"},
		{"surrogate pair combines", `k: "\ud83d\ude00"`, "k", "\U0001F600"},
		{"\\xXX decodes (Latin-1)", `k: "\x41"`, "k", "A"},
		{"\\UXXXXXXXX decodes", `k: "\U0001F600"`, "k", "\U0001F600"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node, err := Parse([]byte(tc.in))
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.in, err)
			}
			if got := node.Get(tc.key).String(); got != tc.want {
				t.Fatalf("value = %q, want %q", got, tc.want)
			}
		})
	}
}

// Controls: existing behavior must be preserved — single-char escapes decode,
// unknown escapes stay literal, malformed short \u stays literal, and
// single-quoted strings remain escape-free.
func TestYAMLUnicodeEscapeControlsUnchanged(t *testing.T) {
	cases := []struct {
		name string
		in   string
		key  string
		want string
	}{
		{"\\n newline decodes", `msg: "a\nb"`, "msg", "a\nb"},
		{"unknown escape stays literal", `q: "a\qb"`, "q", `a\qb`},
		{"short \\u stays literal", `short: "\u12zz"`, "short", `\u12zz`},
		{"single-quoted stays literal", `s: 'caf\u00e9'`, "s", `caf\u00e9`},
		{"double-quoted backslash decodes", `win: "C:\\Users\\test"`, "win", `C:\Users\test`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node, err := Parse([]byte(tc.in))
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.in, err)
			}
			if got := node.Get(tc.key).String(); got != tc.want {
				t.Fatalf("value = %q, want %q", got, tc.want)
			}
		})
	}
}

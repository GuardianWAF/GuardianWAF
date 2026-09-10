package config

import "testing"

// Regression: the YAML scanner treated backslash as an escape character inside
// SINGLE-quoted strings, but YAML single-quoted strings have no backslash
// escapes (only '' is special). A value like 'C:\tools\' swallowed its own
// closing quote, which (a) folded any following inline comment into the
// configured value and (b) made flow-sequence splitting swallow the delimiter
// comma, merging list items. The escape flag is now honored only inside
// double-quoted strings, where backslash escapes are real YAML syntax.

func TestYAMLSingleQuotedTrailingBackslashStripsComment(t *testing.T) {
	node, err := Parse([]byte(`path: 'C:\tools\' # tools directory`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := node.Get("path").String()
	if got != `C:\tools\` {
		t.Fatalf("path = %q, want %q — inline comment leaked into the value", got, `C:\tools\`)
	}
}

func TestYAMLFlowSequenceSingleQuotedTrailingBackslash(t *testing.T) {
	node, err := Parse([]byte(`list: [a, 'b\', c]`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	items := node.Get("list").Slice()
	if len(items) != 3 {
		t.Fatalf("list has %d items, want 3 (delimiter comma was swallowed)", len(items))
	}
	want := []string{"a", `b\`, "c"}
	for i := range want {
		if got := items[i].String(); got != want[i] {
			t.Fatalf("item %d = %q, want %q", i, got, want[i])
		}
	}
}

func TestYAMLBackslashControlsUnchanged(t *testing.T) {
	cases := []struct {
		name string
		in   string
		key  string
		want string
	}{
		{"double-quoted escaped quote keeps # text", `tok: "abc\" # x"`, "tok", `abc" # x`},
		{"double-quoted backslash escapes decode", `path2: "C:\\tools\\"`, "path2", `C:\tools\`},
		{"single-quote doubling escape", "msg: 'it''s alive'", "msg", "it's alive"},
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

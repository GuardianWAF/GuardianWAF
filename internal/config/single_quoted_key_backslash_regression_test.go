package config

import (
	"strconv"
	"strings"
	"testing"
)

func TestYAMLSingleQuotedKeysTreatBackslashesLiterally(t *testing.T) {
	for _, key := range []string{"", "plain", `\`, `C:\tools\`, `C:\tools\\`, `a\: b`, `a\'b\`} {
		for _, quoted := range []string{"'" + strings.ReplaceAll(key, "'", "''") + "'", strconv.Quote(key)} {
			for _, style := range []string{"block", "flow", "sequence"} {
				doc := quoted + ": value"
				if style == "flow" {
					doc = "{" + doc + "}"
				}
				if style == "sequence" {
					doc = "- " + doc
				}
				n, err := Parse([]byte(doc))
				if err != nil {
					t.Fatalf("%s %q: %v", style, quoted, err)
				}
				if style == "sequence" {
					if len(n.Items) != 1 {
						t.Fatalf("%s %q: got %d sequence items", style, quoted, len(n.Items))
					}
					n = n.Items[0]
				}
				if len(n.MapKeys) != 1 || n.MapKeys[0] != key || n.Get(key).String() != "value" {
					t.Fatalf("%s %q: expected key %q=value; got keys %q", style, quoted, key, n.MapKeys)
				}
			}
		}
	}

	control, err := Parse([]byte(`path\:esc: value`))
	if err != nil || control.Get(`path\:esc`).String() != "value" {
		t.Fatalf("bare escaped-colon control: %v", err)
	}
	control, err = Parse([]byte(`'path': 'C:\tools\' # comment`))
	if err != nil || control.Get("path").String() != `C:\tools\` {
		t.Fatalf("single-quoted value control: %v", err)
	}

	n, err := Parse([]byte("waf:\n  canary:\n    metadata:\n      'C:\\tools\\': value\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, n); err != nil {
		t.Fatal(err)
	}
	if cfg.WAF.Canary.Metadata[`C:\tools\`] != "value" {
		t.Fatalf("canary metadata: got %v", cfg.WAF.Canary.Metadata)
	}
	t.Log("FIX VERIFIED")
}

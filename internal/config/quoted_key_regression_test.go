package config

import (
	"strings"
	"testing"
)

func TestYAMLSingleQuotedKeysDecodeApostrophes(t *testing.T) {
	for _, key := range []string{"plain", "team's name", "'edge'", "a''b", "team's: tag", `C:\path`, ""} {
		quoted := "'" + strings.ReplaceAll(key, "'", "''") + "'"
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
				t.Fatalf("%s %q: %v", style, key, err)
			}
			if style == "sequence" {
				n = n.Items[0]
			}
			if len(n.MapKeys) != 1 || n.MapKeys[0] != key || n.Get(key).String() != "value" {
				t.Fatalf("%s key %q got %q", style, key, n.MapKeys)
			}
		}
	}
	n, err := Parse([]byte("'team''s': first\n\"team's\": second\n"))
	if err != nil || len(n.MapKeys) != 1 || n.Get("team's").String() != "second" {
		t.Fatalf("decoded duplicate identity: %v", err)
	}
	t.Log("FIX VERIFIED")
}

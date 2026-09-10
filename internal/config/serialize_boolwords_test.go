package config

import (
	"strings"
	"testing"
)

// Regression: needsQuoting quoted "true"/"false"/"null"/"~" but not the
// yes/no/on/off boolean words, which the YAML parser coerces to bool nodes
// CASE-INSENSITIVELY (makeScalar matches on strings.ToLower). A string field
// holding "Off" was emitted unquoted by MarshalYAML and reloaded as a
// bool-typed "off" — silently case-mangled/typified across a dashboard
// save/load cycle. SaveFile → Parse must round-trip string values exactly.

func TestMarshalYAMLQuotesBooleanWordsCaseInsensitive(t *testing.T) {
	cases := []string{"Off", "NO", "on", "Yes", "oN", "OFF", "yes"}
	for _, word := range cases {
		t.Run(word, func(t *testing.T) {
			cfg := &Config{}
			cfg.Logging.Format = word
			data := MarshalYAML(cfg)

			line := emittedFormatLine(t, data)
			if !strings.Contains(line, `format: "`+word+`"`) {
				t.Fatalf("emitted %q, want the value quoted (format: %q)", line, word)
			}

			node, err := Parse([]byte(data))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := node.GetPath("logging", "format").String(); got != word {
				t.Fatalf("round-trip = %q, want %q — value corrupted across save/load", got, word)
			}
		})
	}
}

// Control: ordinary values must stay unquoted, and the pre-existing
// true/false/null/~ quoting must be preserved.
func TestMarshalYAMLBooleanWordControlsUnchanged(t *testing.T) {
	cfg := &Config{}
	cfg.Logging.Format = "json"
	if line := emittedFormatLine(t, MarshalYAML(cfg)); line != "format: json" {
		t.Fatalf("ordinary value should stay unquoted, got %q", line)
	}

	cfg2 := &Config{}
	cfg2.Logging.Format = "true"
	if line := emittedFormatLine(t, MarshalYAML(cfg2)); line != `format: "true"` {
		t.Fatalf(`"true" should stay quoted, got %q`, line)
	}
}

func emittedFormatLine(t *testing.T, data string) string {
	t.Helper()
	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "format:") {
			return strings.TrimSpace(line)
		}
	}
	t.Fatalf("no format line found in marshaled config:\n%s", data)
	return ""
}

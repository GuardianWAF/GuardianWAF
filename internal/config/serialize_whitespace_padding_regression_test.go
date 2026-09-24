package config

// Regression (round 2026-09-24-r12-yaml-whitespace): needsQuoting never
// checked whitespace padding, so " x", "x " and "   " were emitted UNQUOTED
// on all three String emission paths (marshalField, marshalSlice,
// marshalInlineField flow style). The parser's makeScalar opens with
// strings.TrimSpace before classification, so the padding was silently
// dropped on reload — and a spaces-only value degraded to IsNull/empty.
// Post-fix padded strings are quoted (the round-5/12 yes/no/on/off
// precedent: over-quoting is harmless; a quoted scalar parses back to the
// exact string).

import (
	"strings"
	"testing"
)

func findWhitespacePadLine(t *testing.T, data, substr string) string {
	t.Helper()
	for _, line := range strings.Split(data, "\n") {
		if strings.Contains(line, substr) {
			return strings.TrimSpace(line)
		}
	}
	t.Fatalf("no line containing %q in marshaled config:\n%s", substr, data)
	return ""
}

func TestMarshalYAMLQuotesWhitespacePaddedStrings(t *testing.T) {
	// Case A: flow-style slice items.
	cfg := &Config{}
	cfg.VirtualHosts = []VirtualHostConfig{{Domains: []string{" x", "x ", "   "}}}
	data := MarshalYAML(cfg)
	got := findWhitespacePadLine(t, data, "domains:")
	want := `- domains: [" x", "x ", "   "]`
	if got != want {
		t.Fatalf("whitespace-padded flow items not quoted — padding is lost on reload;\ngot:  %s\nwant: %s", got, want)
	}
	node, err := Parse([]byte(data))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	vh := node.MapItems["virtual_hosts"]
	domains := vh.Items[0].MapItems["domains"]
	if domains == nil || len(domains.Items) != 3 ||
		domains.Items[0].String() != " x" || domains.Items[1].String() != "x " || domains.Items[2].String() != "   " {
		t.Fatalf("flow items round-trip corrupted: %#v", domains)
	}

	// Case B: block-style slice item.
	cfg2 := &Config{}
	cfg2.TrustedProxies = []string{" x "}
	got2 := findWhitespacePadLine(t, MarshalYAML(cfg2), `" x "`)
	if got2 != `- " x "` {
		t.Fatalf("whitespace-padded block item not quoted;\ngot:  %s\nwant: %s", got2, `- " x "`)
	}

	// Case C: plain key-value string field.
	cfg3 := &Config{}
	cfg3.Logging.Format = " x "
	got3 := findWhitespacePadLine(t, MarshalYAML(cfg3), "format:")
	if !strings.Contains(got3, `format: " x "`) {
		t.Fatalf("whitespace-padded plain field not quoted: %q", got3)
	}

	// Controls: ordinary values stay unquoted; the round-5/12 boolean-word
	// quoting is unaffected.
	cfg4 := &Config{}
	cfg4.VirtualHosts = []VirtualHostConfig{{Domains: []string{"plain.example.com"}}}
	if line := findWhitespacePadLine(t, MarshalYAML(cfg4), "domains:"); !strings.HasSuffix(line, "domains: [plain.example.com]") {
		t.Fatalf("ordinary item should stay unquoted, got %q", line)
	}
	cfg5 := &Config{}
	cfg5.Logging.Format = "Off"
	if line := findWhitespacePadLine(t, MarshalYAML(cfg5), "format:"); !strings.Contains(line, `format: "Off"`) {
		t.Fatalf("round-5/12 boolean-word quoting regressed: %q", line)
	}
}

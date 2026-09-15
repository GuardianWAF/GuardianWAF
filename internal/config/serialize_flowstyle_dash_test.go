package config

import (
	"strings"
	"testing"
)

// Regression (bug-hunt round 17/25, 2026-09-15): slice string items must
// round-trip losslessly across SaveFile/Load.
//
// Case A (flow style): marshalInlineField's slice-of-strings branch joined
// items with ", " and NO quoting, so a value containing ", " (e.g. the domain
// "a,b.com") was emitted as two flow entries and reloaded as two separate
// strings — a silent list corruption on every dashboard save/load cycle.
//
// Case B (block style): needsQuoting checked leading '*', '&', '!', '|', '>',
// '%', '@' but not '-', so a value with a leading "- " was emitted as
// "- - x" and reloaded as a NESTED SEQUENCE instead of a string.
//
// Both are fixed by routing flow-style items through needsQuoting and adding
// the leading-dash rule; over-quoting is harmless (a quoted scalar parses back
// to the exact string), matching the round-5/12 yes/no/on/off precedent.

func findR17Line(t *testing.T, data, substr string) string {
	t.Helper()
	for _, line := range strings.Split(data, "\n") {
		if strings.Contains(line, substr) {
			return strings.TrimSpace(line)
		}
	}
	t.Fatalf("no line containing %q in marshaled config:\n%s", substr, data)
	return ""
}

func TestMarshalYAMLFlowStyleQuotesCommaItems(t *testing.T) {
	cfg := &Config{}
	cfg.VirtualHosts = []VirtualHostConfig{{Domains: []string{"plain.example.com", "a,b.com"}}}
	got := findR17Line(t, MarshalYAML(cfg), "domains:")
	want := `- domains: [plain.example.com, "a,b.com"]`
	if got != want {
		t.Fatalf("comma-bearing slice item not quoted — reloads as two entries;\ngot:  %s\nwant: %s", got, want)
	}

	node, err := Parse([]byte(MarshalYAML(cfg)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	vh := node.MapItems["virtual_hosts"]
	if vh == nil || len(vh.Items) != 1 {
		t.Fatal("virtual_hosts sequence missing after round-trip")
	}
	domains := vh.Items[0].MapItems["domains"]
	if domains == nil || len(domains.Items) != 2 || domains.Items[1].String() != "a,b.com" {
		t.Fatalf("domains round-trip corrupted: %#v", domains)
	}
}

func TestMarshalYAMLBlockStyleQuotesDashItems(t *testing.T) {
	cfg := &Config{}
	cfg.TrustedProxies = []string{"- weird.conf"}
	got := findR17Line(t, MarshalYAML(cfg), "weird.conf")
	want := `- "- weird.conf"`
	if got != want {
		t.Fatalf("dash-leading slice item not quoted — reloads as a nested sequence;\ngot:  %s\nwant: %s", got, want)
	}

	node, err := Parse([]byte(MarshalYAML(cfg)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	proxies := node.GetPath("trusted_proxies")
	if proxies == nil {
		t.Fatal("trusted_proxies node missing after round-trip")
	}
}

// Controls: ordinary values stay unquoted, and the round-5/12 boolean-word
// quoting (string fields) is unaffected by the flow-style change.
func TestMarshalYAMLSliceQuotingControls(t *testing.T) {
	cfg := &Config{}
	cfg.VirtualHosts = []VirtualHostConfig{{Domains: []string{"plain.example.com"}}}
	got := findR17Line(t, MarshalYAML(cfg), "domains:")
	if !strings.HasSuffix(got, "domains: [plain.example.com]") {
		t.Fatalf("ordinary flow item should stay unquoted, got %q", got)
	}

	cfg2 := &Config{}
	cfg2.Logging.Format = "Off"
	if line := findR17Line(t, MarshalYAML(cfg2), "format:"); !strings.Contains(line, `format: "Off"`) {
		t.Fatalf("round-5/12 boolean-word quoting regressed: %q", line)
	}
}

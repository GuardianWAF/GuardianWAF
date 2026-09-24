package config

// Regression (round 2026-09-24-r15-map-key-quoting): marshalMap emitted map
// keys raw while VALUES routed through needsQuoting. Lossy shapes: a key
// containing colon+space ("a b: c") splits at the inner colon on reload
// (key truncated, value polluted), and a whitespace-padded key (" x")
// shifts the emitted line's indent so the reload Parse errors — SaveFile
// bricks the next load. Free-form user keys (Metadata, Fields,
// CustomPatterns, Headers) make both shapes reachable. Post-fix map keys
// route through needsQuoting too; the parser already strips quoted keys
// (unquoteKey), so over-quoting is harmless (the round-5/12 precedent).

import (
	"strings"
	"testing"
)

func TestMarshalYAMLQuotesMapKeys(t *testing.T) {
	cfg := &Config{}
	cfg.WAF.Canary.Metadata = map[string]string{
		"a b: c": "v1",
		" x":     "v2",
		"x ":     "v3",
		"plain":  "v4",
	}
	data := MarshalYAML(cfg)

	// Post-fix: each lossy key is quoted on its own emitted line.
	for _, want := range []string{`"a b: c": v1`, `" x": v2`, `"x ": v3`} {
		if !strings.Contains(data, want) {
			t.Fatalf("lossy map key not quoted — want line containing %q in:\n%s", want, data)
		}
	}
	// Control: the ordinary key stays unquoted.
	if !strings.Contains(data, "plain: v4") {
		t.Fatalf("control: plain key/value line missing from:\n%s", data)
	}

	node, err := Parse([]byte(data))
	if err != nil {
		t.Fatalf("Parse error on our own saved config (save bricks the next load): %v", err)
	}
	pat := node.GetPath("waf", "canary", "metadata")
	if pat == nil {
		t.Fatal("metadata node missing after round-trip")
	}
	for _, key := range []string{"a b: c", " x", "x ", "plain"} {
		if pat.Get(key) == nil {
			t.Fatalf("key %q missing after round-trip", key)
		}
	}
	if v := pat.Get("a b: c"); v == nil || v.String() != "v1" {
		t.Fatalf("key/value round-trip corrupted for \"a b: c\": %#v", v)
	}
}

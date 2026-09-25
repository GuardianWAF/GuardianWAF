package config

// Regression fuzz (round 2026-09-25-round6-yaml-roundtrip-fuzz): lossless
// round-trip instrument over the three scalar emission paths — whatever
// MarshalYAML emits must Parse back to the identical value. The serializer
// quoting family was found manually (round-5/12 yes/no words, round-12
// whitespace padding, round-15 map keys, round-17 flow-style dash); this
// property covers the family for arbitrary strings and found its next three
// members: (1) a value containing an invalid UTF-8 byte was emitted RAW and
// UNQUOTED, and Parse (correctly, utf8.Valid) rejected the whole document —
// SaveFile would have written a config that fails the next boot. needsQuoting
// now forces invalid UTF-8 onto the quoted path, where %q escapes the bytes
// as \xNN the parser's double-quoted scalar decoder accepts; byte-exact
// preservation is impossible in a text format, so invalid inputs assert
// boot-safety (reparse) only. (2) A raw carriage return was likewise emitted
// unquoted and broke the flow-sequence scanner ("invalid flow sequence") —
// the special-char rule covered only \n; it now quotes every C0 control and
// DEL, all escaped in forms unescapeDoubleQuoted decodes; (3) a literal $ in a
// value corrupted on reload — the parser expands $$ escapes and ${VAR}
// references in EVERY scalar form including quoted ones (expandEnvVars),
// so the serializer now dollar-doubles every emitted scalar value ($ ->
// $$); keys are exempt (unquoteKey never expands). The crasher corpus
// entries under testdata/fuzz/FuzzYAMLRoundTrip are kept as permanent
// regression inputs.
//
// Round 2026-09-25-round7-key-escape-decode extended the instrument with a
// MAP emission path (Features — the one emitted map field on top-level
// Config) and found the family's key-side member: keys quoted by
// needsQuoting emitted %q escapes (backslash, control chars, quotes) that
// unquoteKey reloaded WITHOUT decoding — silent key corruption on every
// save/reload cycle — and a key containing a raw backslash was emitted
// unquoted entirely (no backslash rule), where parseKeyValue's escape-aware
// colon scanner consumed the "\:" separator and the document failed to
// reparse (unbootable save). Fixed on both halves: needsQuoting now quotes
// any string containing a backslash, and unquoteKey decodes double-quoted
// keys via unescapeDoubleQuoted (single-quoted keys stay literal per YAML;
// keys remain env-expansion-free by design).
//
// Round 2026-09-25-round8-inline-map-roundtrip added the INLINE map emission
// path (Alerting.Webhooks[i].Headers — the r16 seam: marshalInlineField's Map
// case emits flow style {k: v} inside a sequence-item struct; keys quote via
// needsQuoting, values dollar-double, reload routes through parseFlowMap).

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func fuzzRoundTripConfig(s string) *Config {
	cfg := &Config{}
	cfg.Logging.Format = s
	cfg.TrustedProxies = []string{s}
	cfg.VirtualHosts = []VirtualHostConfig{{Domains: []string{s}}}
	// Map emission path (round 2026-09-25-round7-key-escape-decode): Features
	// is the one emitted map field on top-level Config. Keys go through the
	// shared needsQuoting gate (so control-char/invalid-UTF-8 keys emit as %q
	// escapes) but the reload key strip (unquoteKey) is the asymmetry under
	// test; the bool value keeps the harness minimal.
	cfg.Features = map[string]bool{s: true}
	// Inline-map emission path (round 2026-09-25-round8-inline-map-roundtrip):
	// WebhookConfig.Headers is the r16 seam — marshalInlineField's Map case
	// emits flow style {k: v} inside a sequence-item struct; keys quote via
	// needsQuoting, values dollar-double, reload routes through parseFlowMap.
	// Fixed name/URL keep the assertion targeted on the Headers map.
	cfg.Alerting = AlertingConfig{
		Enabled: true,
		Webhooks: []WebhookConfig{{
			Name:    "roundtrip-probe",
			URL:     "http://127.0.0.1/hook",
			Headers: map[string]string{s: s},
		}},
	}
	return cfg
}

func FuzzYAMLRoundTrip(f *testing.F) {
	seeds := []string{
		"", " ", "   ", " x", "x ", " x ", "plain", "yes", "no", "on", "off",
		"null", "~", "true", "123", "1.5", "0x10", "1e3",
		"a:b", "a: b", "#hash", " #hash", "- dash", "-dash", "a,b",
		"[bracket]", "{brace}", "*star", "&amp", "!bang", "|pipe", ">gt",
		"'quote'", `"dquote"`, "%pct", "@at", "`tick",
		"https://example.com/path?q=1&r=2",
		"line1\nline2", "tab\there", "trailing\\", "c:\\path",
		"café", "日本語", "emoji😀", "0\r0", "$$", "$HOME", "${VAR}",
		"\x84", "\xff\xfe", "ok\xffbad",
		strings.Repeat("x", 500),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 500 {
			return
		}
		cfg := fuzzRoundTripConfig(s)
		y1 := MarshalYAML(cfg)
		node, err := Parse([]byte(y1))
		if err != nil {
			t.Fatalf("FAIL: marshaled config does not reparse (s=%q):\nyaml=%q\nerr=%v", s, y1, err)
		}
		if !utf8.ValidString(s) {
			// Invalid UTF-8 cannot survive a text format byte-exact; the
			// contract for such inputs is boot-safety: the emitted config
			// must reparse (the escapes decode to the best-effort text form).
			return
		}
		// Absent keys reload to the zero value, so resolve-with-default is
		// the exact lossless-reload contract: a zero-valued struct section is
		// elided by MarshalYAML and "" must come back as "".
		got := ""
		if loggingNode := node.MapItems["logging"]; loggingNode != nil && loggingNode.MapItems["format"] != nil {
			got = loggingNode.MapItems["format"].String()
		}
		if got != s {
			t.Fatalf("FAIL: plain field round-trip corrupted (s=%q)\nyaml=%q\ngot=%q", s, y1, got)
		}
		proxies := node.MapItems["trusted_proxies"]
		if proxies == nil || len(proxies.Items) != 1 || proxies.Items[0].String() != s {
			t.Fatalf("FAIL: block slice round-trip corrupted (s=%q)\nyaml=%q\ngot=%#v", s, y1, proxies)
		}
		vh := node.MapItems["virtual_hosts"]
		if vh == nil || len(vh.Items) != 1 {
			t.Fatalf("FAIL: virtual_hosts lost on round-trip (s=%q)\nyaml=%q", s, y1)
		}
		domains := vh.Items[0].MapItems["domains"]
		if domains == nil || len(domains.Items) != 1 || domains.Items[0].String() != s {
			t.Fatalf("FAIL: flow slice round-trip corrupted (s=%q)\nyaml=%q\ngot=%#v", s, y1, domains)
		}
		feats := node.MapItems["features"]
		if feats == nil || len(feats.MapItems) != 1 {
			t.Fatalf("FAIL: features map lost on round-trip (s=%q)\nyaml=%q\ngot=%v", s, y1, feats)
		}
		if feats.MapItems[s] == nil {
			t.Fatalf("FAIL: map key corrupted on reload (s=%q)\nyaml=%q\ngot keys=%v", s, y1, feats.MapKeys)
		}
		wh := node.MapItems["alerting"].MapItems["webhooks"]
		if wh == nil || len(wh.Items) != 1 {
			t.Fatalf("FAIL: webhooks lost on round-trip (s=%q)\nyaml=%q\ngot=%v", s, y1, wh)
		}
		hdrs := wh.Items[0].MapItems["headers"]
		if hdrs == nil || len(hdrs.MapItems) != 1 {
			t.Fatalf("FAIL: inline headers map lost on round-trip (s=%q)\nyaml=%q\ngot=%v", s, y1, hdrs)
		}
		if hdrs.MapItems[s] == nil {
			t.Fatalf("FAIL: inline map key corrupted on reload (s=%q)\nyaml=%q\ngot keys=%v", s, y1, hdrs.MapKeys)
		}
		if hdrs.MapItems[s].String() != s {
			t.Fatalf("FAIL: inline map value corrupted on reload (s=%q)\nyaml=%q\ngot=%q", s, y1, hdrs.MapItems[s].String())
		}
	})
}

// Deterministic pin for the crasher corpus entry: invalid UTF-8 must be
// escaped, and the emitted config must reparse.
func TestMarshalYAMLEscapesInvalidUTF8(t *testing.T) {
	cfg := fuzzRoundTripConfig("\x84")
	y := MarshalYAML(cfg)
	if !utf8.ValidString(y) {
		t.Fatalf("marshaled output still contains invalid UTF-8: %q", y)
	}
	if _, err := Parse([]byte(y)); err != nil {
		t.Fatalf("marshaled config with invalid UTF-8 must reparse: %v\nyaml=%q", err, y)
	}
}

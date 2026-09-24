package config

// Regression (round 2026-09-24-r16-inline-map-drop): marshalInlineField's
// switch had no reflect.Map case, so a map field inside a sequence-item
// struct (e.g. WebhookConfig Headers, reached via the marshalSlice Struct
// branch) was silently skipped — nothing emitted, no error — and the
// reload left it nil: silent data loss on every save. Post-fix the Map
// case emits flow style (keys AND values through needsQuoting, the
// round-15/12 lessons); the parser already routes "{...}" values to
// parseFlowMap, which strips quoted keys (unquoteKey-style).

import (
	"testing"
)

func TestMarshalYAMLKeepsMapFieldsInSliceStructs(t *testing.T) {
	cfg := &Config{}
	cfg.Alerting.Webhooks = []WebhookConfig{{
		Name:    "sink",
		URL:     "https://hooks.example.internal/sink",
		Type:    "generic",
		Events:  []string{"block"},
		Headers: map[string]string{"X-Tenant": "acme", "a b: c": "v2"},
	}}
	data := MarshalYAML(cfg)

	node, err := Parse([]byte(data))
	if err != nil {
		t.Fatalf("Parse error on our own saved config: %v\n%s", err, data)
	}
	wh := node.GetPath("alerting", "webhooks")
	if wh == nil || len(wh.Items) == 0 {
		t.Fatalf("webhooks sequence missing after round-trip:\n%s", data)
	}
	item := wh.Items[0]
	if item == nil || item.Get("name") == nil || item.Get("name").String() != "sink" {
		t.Fatalf("control: webhook scalar fields did not round-trip:\n%s", data)
	}
	hdrs := item.Get("headers")
	if hdrs == nil {
		t.Fatalf("headers map silently dropped by MarshalYAML:\n%s", data)
	}
	if v := hdrs.Get("X-Tenant"); v == nil || v.String() != "acme" {
		t.Fatalf("headers entry X-Tenant lost on round-trip:\n%s", data)
	}
	if v := hdrs.Get("a b: c"); v == nil || v.String() != "v2" {
		t.Fatalf("quoted-shape headers key \"a b: c\" lost or corrupted on round-trip:\n%s", data)
	}
}

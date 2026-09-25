package siem

// Regression for round 2026-09-25-r2-siem-extra-fields: ExporterConfig.ExtraFields
// (config siem.fields) was plumbed through ExporterConfigFromSIEM but never
// consumed — formatEvent silently dropped the documented static enrichment
// fields (ADR 0025: "Operators can inject static fields into every exported
// event for SIEM correlation") from both CEF and JSON records. Wired:
//   - CEF: sorted, escapeCEF-escaped " k=v" pairs appended to the extension;
//   - JSON: nested under a dedicated "extra" object (omitted when unset), so
//     fixed event keys can never be shadowed and empty-config output stays
//     byte-identical.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func extraFieldsEvent() engine.Event {
	return engine.Event{
		ID: "r2-evt", Timestamp: time.Now(), ClientIP: "10.9.0.2:55555",
		Method: "POST", Path: "/r2-path", Query: "a=1", UserAgent: "r2UA/1.0",
		Host: "r2.example", Score: 75, Action: engine.ActionBlock,
	}
}

func extraFieldsExporter(format string, extra map[string]string) *Exporter {
	return &Exporter{cfg: ExporterConfig{
		Format:      format,
		ExtraFields: extra,
		Hostname:    "r2host",
	}}
}

// CEF: configured extras are appended as sorted, escaped extension pairs —
// keys and values both go through escapeCEF.
func TestFormatEvent_CEFAppendsSortedEscapedExtraFields(t *testing.T) {
	exp := extraFieldsExporter("cef", map[string]string{
		"datacenter": "dc1", "env": "prod|x", "weird=key": "v",
	})
	line := exp.formatEvent(extraFieldsEvent())
	for _, want := range []string{" datacenter=dc1", " env=prod\\|x", " weird\\=key=v"} {
		if !strings.Contains(line, want) {
			t.Fatalf("FAIL: CEF record missing extra pair %q: %q", want, line)
		}
	}
	i1 := strings.Index(line, "datacenter=dc1")
	i2 := strings.Index(line, "env=prod\\|x")
	i3 := strings.Index(line, "weird\\=key=v")
	if i1 < 0 || i2 < 0 || i3 < 0 || !(i1 < i2 && i2 < i3) {
		t.Fatalf("FAIL: CEF extra pairs not in sorted deterministic order: %q", line)
	}
}

// CEF control: with no extras configured the record is exactly EncodeCEF's
// output — both nil and the shipped default's empty non-nil map.
func TestFormatEvent_CEFWithoutExtraFieldsUnchanged(t *testing.T) {
	ev := extraFieldsEvent()
	for _, extra := range []map[string]string{nil, {}} {
		exp := extraFieldsExporter("cef", extra)
		if got, want := exp.formatEvent(ev), EncodeCEF(ev, "GuardianWAF", version); got != want {
			t.Fatalf("FAIL: CEF output changed with no extras configured:\n got  %q\n want %q", got, want)
		}
	}
}

// JSON: extras nest under "extra"; top-level event keys are never shadowed
// even when an extra field reuses a fixed key name.
func TestFormatEvent_JSONExtrasNestedNotShadowed(t *testing.T) {
	exp := extraFieldsExporter("json", map[string]string{
		"datacenter": "dc1", "path": "FAKE", "score": "FAKE",
	})
	line := exp.formatEvent(extraFieldsEvent())
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("FAIL: JSON record unparseable: %v — %q", err, line)
	}
	if m["path"] != "/r2-path" {
		t.Fatalf("FAIL: top-level path shadowed: %v — %q", m["path"], line)
	}
	if m["score"] != float64(75) {
		t.Fatalf("FAIL: top-level score shadowed: %v — %q", m["score"], line)
	}
	extra, ok := m["extra"].(map[string]any)
	if !ok || extra["datacenter"] != "dc1" || extra["path"] != "FAKE" || extra["score"] != "FAKE" {
		t.Fatalf("FAIL: JSON extras missing or wrong: %q", line)
	}
}

// JSON control: with no extras configured there is no "extra" key at all.
func TestFormatEvent_JSONWithoutExtraFieldsUnchanged(t *testing.T) {
	ev := extraFieldsEvent()
	for _, extra := range []map[string]string{nil, {}} {
		exp := extraFieldsExporter("json", extra)
		line := exp.formatEvent(ev)
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("FAIL: JSON record unparseable: %v — %q", err, line)
		}
		if _, exists := m["extra"]; exists {
			t.Fatalf("FAIL: \"extra\" key present with no extras configured: %q", line)
		}
	}
}

// Wire-level: configured extras reach a real collector on the CEF path.
func TestExporter_ExtraFieldsReachTheWire(t *testing.T) {
	addr, _, received := startMockSyslog(t)
	exp, err := NewExporter(ExporterConfig{
		Endpoint:      addr,
		Format:        "cef",
		FlushInterval: 50 * time.Millisecond,
		BatchSize:     10,
		Timeout:       2 * time.Second,
		ExtraFields:   map[string]string{"datacenter": "dc1"},
	})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	exp.Export(extraFieldsEvent())
	if err := exp.Close(); err != nil {
		t.Fatalf("close exporter: %v", err)
	}
	var line string
	select {
	case line = <-received:
	case <-time.After(5 * time.Second):
		t.Fatalf("FAIL: no SIEM record arrived within 5s")
	}
	if !strings.Contains(line, "datacenter=dc1") {
		t.Fatalf("FAIL: configured extra field missing on the wire: %q", line)
	}
}

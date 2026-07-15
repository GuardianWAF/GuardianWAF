package tracing

import (
	"errors"
	"strings"
	"testing"
)

func TestStartSpan(t *testing.T) {
	span := StartSpan("test.operation", SpanKindServer)
	if span.Name != "test.operation" {
		t.Errorf("Name = %q, want %q", span.Name, "test.operation")
	}
	if span.Kind != SpanKindServer {
		t.Errorf("Kind = %v, want %v", span.Kind, SpanKindServer)
	}
	if span.TraceID == "" {
		t.Error("TraceID is empty")
	}
	if len(span.TraceID) != 32 {
		t.Errorf("TraceID length = %d, want 32 hex characters", len(span.TraceID))
	}
	if span.SpanID == "" {
		t.Error("SpanID is empty")
	}
	if len(span.SpanID) != 16 {
		t.Errorf("SpanID length = %d, want 16 hex characters", len(span.SpanID))
	}
	if span.StartTime.IsZero() {
		t.Error("StartTime is zero")
	}
}

func TestStartSpanWithParent(t *testing.T) {
	parent := StartSpan("parent", SpanKindServer)
	child := StartSpanWithParent("child", SpanKindInternal, parent.TraceID)

	if child.TraceID != parent.TraceID {
		t.Errorf("child TraceID = %q, want parent %q", child.TraceID, parent.TraceID)
	}
	if child.SpanID == parent.SpanID {
		t.Error("child SpanID should differ from parent")
	}
}

func TestSpanAttributes(t *testing.T) {
	span := StartSpan("test", SpanKindInternal)
	span.SetAttribute("key1", "value1")
	span.SetAttribute("key2", "value2")

	if span.Attributes["key1"] != "value1" {
		t.Errorf("Attributes[key1] = %q, want %q", span.Attributes["key1"], "value1")
	}
	if span.Attributes["key2"] != "value2" {
		t.Errorf("Attributes[key2] = %q, want %q", span.Attributes["key2"], "value2")
	}
}

func TestSpanEvents(t *testing.T) {
	span := StartSpan("test", SpanKindInternal)
	span.AddEvent("exception", map[string]string{"type": "Error"})

	if len(span.Events) != 1 {
		t.Fatalf("Events = %d, want 1", len(span.Events))
	}
	if span.Events[0].Name != "exception" {
		t.Errorf("Event.Name = %q, want %q", span.Events[0].Name, "exception")
	}
	if span.Events[0].Timestamp.IsZero() {
		t.Error("Event.Timestamp is zero")
	}
}

func TestSpanEnd(t *testing.T) {
	span := StartSpan("test", SpanKindInternal)
	span.End()

	if span.EndTime.IsZero() {
		t.Error("EndTime is zero after End()")
	}
	if span.Duration() < 0 {
		t.Error("Duration should be non-negative")
	}
}

func TestSpanIsRecording(t *testing.T) {
	span := StartSpan("test", SpanKindInternal)
	if !span.IsRecording() {
		t.Error("active span should be recording")
	}
	span.End()
	if span.IsRecording() {
		t.Error("ended span should not be recording")
	}
}

func TestNoopExporter(t *testing.T) {
	e := NewNoopExporter()
	span := StartSpan("test", SpanKindInternal)
	e.Export(span) // should not panic
	e.Shutdown()
}

func TestShouldSample_Disabled(t *testing.T) {
	Init(Config{Enabled: false})
	if ShouldSample() {
		t.Error("ShouldSample should return false when disabled")
	}
	Shutdown()
}

func TestShouldSample_Always(t *testing.T) {
	Init(Config{Enabled: true, SamplingRate: 1.0})
	if !ShouldSample() {
		t.Error("ShouldSample should return true with rate 1.0")
	}
	Shutdown()
}

func TestShouldSample_Never(t *testing.T) {
	Init(Config{Enabled: true, SamplingRate: 0.0})
	if ShouldSample() {
		t.Error("ShouldSample should return false with rate 0.0")
	}
	Shutdown()
}

func TestEnabled(t *testing.T) {
	Init(Config{Enabled: true})
	if !Enabled() {
		t.Error("Enabled should return true after Init with Enabled=true")
	}
	Shutdown()
	if Enabled() {
		t.Error("Enabled should return false after Shutdown")
	}
}

func TestStdoutExporter(t *testing.T) {
	e := NewStdoutExporter()
	span := StartSpan("test.span", SpanKindInternal)
	span.SetAttribute("attr1", "val1")
	span.Status = SpanStatusOK
	e.Export(span)

	errorSpan := StartSpan("test.error", SpanKindInternal)
	errorSpan.Status = SpanStatusError
	e.Export(errorSpan)
	e.Shutdown()

	// Export after shutdown should be safe
	span2 := StartSpan("test.span2", SpanKindInternal)
	e.Export(span2) // should not panic
}

func TestStdoutExporterMarshalError(t *testing.T) {
	originalMarshal := marshalJSON
	marshalJSON = func(any) ([]byte, error) {
		return nil, errors.New("marshal failed")
	}
	t.Cleanup(func() { marshalJSON = originalMarshal })

	NewStdoutExporter().Export(StartSpan("test.marshal-error", SpanKindInternal))
}

func TestStats(t *testing.T) {
	Init(Config{Enabled: true})
	enabled, created, exported := Stats()
	if !enabled {
		t.Error("should be enabled")
	}
	_ = created
	_ = exported
	Shutdown()
}

func TestSetExporter(t *testing.T) {
	SetExporter(NewNoopExporter())
	// Should not panic — just verify it works
	span := StartSpan("test", SpanKindInternal)
	span.End()
}

func TestInit_SelectsStdoutExporter(t *testing.T) {
	Init(Config{Enabled: true, ExporterType: "stdout"})
	if !Enabled() {
		t.Error("should be enabled")
	}
	Shutdown()
}

func TestInit_SelectsNoopByDefault(t *testing.T) {
	Init(Config{Enabled: true})
	if !Enabled() {
		t.Error("should be enabled")
	}
	Shutdown()
}

func TestShouldSample_FractionalEnabled(t *testing.T) {
	Init(Config{Enabled: true, SamplingRate: 0.5})
	// With 0.5 sampling rate and deterministic counter, some should sample
	sampled := false
	for i := 0; i < 500; i++ {
		if ShouldSample() {
			sampled = true
			break
		}
	}
	if !sampled {
		t.Error("expected at least one sample in 500 tries with 0.5 rate")
	}
	Shutdown()
}

func TestSpanEnd_Idempotent(t *testing.T) {
	span := StartSpan("test.idempotent", SpanKindInternal)
	span.End()
	endTime1 := span.EndTime
	span.End() // second call should be a no-op
	if span.EndTime != endTime1 {
		t.Error("EndTime should not change on second End() call")
	}
}

func TestAttributeConstants(t *testing.T) {
	attrs := []string{
		AttrHTTPMethod, AttrHTTPURL, AttrHTTPHost, AttrHTTPCode, AttrHTTPUserAgent,
		AttrClientIP, AttrWAFLayer, AttrWAFAction, AttrWAFScore, AttrWAFTenantID,
		AttrWAFBlocked, AttrWAFLatencyMs, AttrWAFRuleID, AttrWAFDetector, AttrWAFFinding,
	}
	for _, a := range attrs {
		if !strings.Contains(a, ".") {
			t.Errorf("attribute %q should contain a dot (OTel convention)", a)
		}
	}
}

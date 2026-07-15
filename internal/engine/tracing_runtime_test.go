package engine

import (
	"math"
	"sync"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/tracing"
)

type collectingTraceExporter struct {
	mu       sync.Mutex
	spans    []*tracing.Span
	shutdown bool
}

func (e *collectingTraceExporter) Export(span *tracing.Span) {
	e.mu.Lock()
	e.spans = append(e.spans, span)
	e.mu.Unlock()
}

func (e *collectingTraceExporter) Shutdown() {
	e.mu.Lock()
	e.shutdown = true
	e.mu.Unlock()
}

func (e *collectingTraceExporter) snapshot() ([]*tracing.Span, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]*tracing.Span(nil), e.spans...), e.shutdown
}

type tracingTestLayer struct{}

func (tracingTestLayer) Name() string                        { return "trace-test" }
func (tracingTestLayer) Order() int                          { return 100 }
func (tracingTestLayer) Process(*RequestContext) LayerResult { return LayerResult{Action: ActionPass} }

func TestEngineTracingConfigProducesRootAndLayerSpans(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Tracing.Enabled = true
	cfg.Tracing.ServiceName = "guardianwaf-test"
	cfg.Tracing.SamplingRate = 1
	cfg.Tracing.ExporterType = "noop"
	eng, _, _ := testEngineWithConfig(t, cfg)
	exporter := &collectingTraceExporter{}
	eng.tracer.SetExporter(exporter)
	eng.AddLayer(OrderedLayer{Layer: tracingTestLayer{}, Order: 100})

	eng.Check(testRequest("GET", "/traced"))
	spans, shutdown := exporter.snapshot()
	if shutdown {
		t.Fatal("trace exporter shut down before engine close")
	}
	if len(spans) != 2 {
		t.Fatalf("exported spans = %d, want root and layer spans", len(spans))
	}
	if spans[0].Name != "trace-test" || spans[0].ParentID == "" {
		t.Fatalf("layer span = %#v, want a parented trace-test span", spans[0])
	}
	if spans[1].Name != "waf.request" || spans[1].Attributes["service.name"] != "guardianwaf-test" {
		t.Fatalf("root span = %#v, want service-tagged waf.request span", spans[1])
	}
	if spans[1].Attributes[tracing.AttrWAFAction] != ActionPass.String() || spans[1].Attributes[tracing.AttrHTTPCode] != "200" {
		t.Fatalf("root span attributes = %#v, want final pass/200 outcome", spans[1].Attributes)
	}
	if spans[0].TraceID != spans[1].TraceID {
		t.Fatalf("child trace ID %q does not match root %q", spans[0].TraceID, spans[1].TraceID)
	}
	_, created, exported := eng.tracer.Stats()
	if created < 2 || exported != 2 {
		t.Fatalf("tracing stats = created %d exported %d, want at least 2/2", created, exported)
	}

	if err := eng.Close(); err != nil {
		t.Fatal(err)
	}
	_, shutdown = exporter.snapshot()
	if !shutdown {
		t.Fatal("engine close did not shut down its trace exporter")
	}
}

func TestEngineReloadRejectsInvalidTracingWithoutChangingRuntime(t *testing.T) {
	eng, _, _ := testEngine(t)
	defer eng.Close()

	cfg := eng.Config()
	cfg.Tracing.Enabled = true
	cfg.Tracing.SamplingRate = 1
	cfg.Tracing.ExporterType = "noop"
	if err := eng.Reload(cfg); err != nil {
		t.Fatalf("Reload(valid tracing) error = %v", err)
	}
	if !eng.tracer.Enabled() {
		t.Fatal("valid tracing reload did not enable the engine tracer")
	}

	invalid := eng.Config()
	invalid.Tracing.SamplingRate = math.NaN()
	if err := eng.Reload(invalid); err == nil {
		t.Fatal("Reload() accepted NaN tracing sampling rate")
	}
	if !eng.tracer.Enabled() {
		t.Fatal("rejected tracing reload changed the active tracer")
	}
}

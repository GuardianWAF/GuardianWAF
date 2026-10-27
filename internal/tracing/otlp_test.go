package tracing

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// collector is a minimal OTLP/HTTP receiver that decodes JSON requests.
type collector struct {
	mu       sync.Mutex
	requests []otlpTraceRequest
	headers  []http.Header
	status   atomic.Int32 // response status; 0 means 200
	hits     atomic.Int32
}

func (c *collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.hits.Add(1)
	if code := c.status.Load(); code != 0 {
		w.WriteHeader(int(code))
		return
	}
	body, _ := io.ReadAll(r.Body)
	var req otlpTraceRequest
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	c.requests = append(c.requests, req)
	c.headers = append(c.headers, r.Header.Clone())
	c.mu.Unlock()
	_, _ = io.WriteString(w, `{}`)
}

func (c *collector) spans() []otlpWireSpan {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []otlpWireSpan
	for _, req := range c.requests {
		for _, rs := range req.ResourceSpans {
			for _, ss := range rs.ScopeSpans {
				out = append(out, ss.Spans...)
			}
		}
	}
	return out
}

func newTestCollector(t *testing.T) (*collector, string) {
	t.Helper()
	c := &collector{}
	srv := httptest.NewServer(c)
	t.Cleanup(srv.Close)
	return c, srv.URL + "/v1/traces"
}

func TestOTLPExporterDeliversSpansInOTLPJSON(t *testing.T) {
	c, endpoint := newTestCollector(t)
	tr, err := NewTracer(Config{
		Enabled: true, ServiceName: "edge-waf", SamplingRate: 1, ExporterType: "otlp",
		OTLP: OTLPConfig{Endpoint: endpoint, Headers: map[string]string{"Authorization": "Bearer t0ken"}, FlushInterval: time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	root := tr.StartSpan("waf.request", SpanKindServer)
	root.SetAttribute(AttrHTTPMethod, "GET")
	child := root.StartChild("detection", SpanKindInternal)
	child.AddEvent("finding", map[string]string{"detector": "sqli"})
	child.Status = SpanStatusError
	child.End()
	root.End()
	tr.Shutdown() // flushes the partial batch

	spans := c.spans()
	if len(spans) != 2 {
		t.Fatalf("collector received %d spans, want 2", len(spans))
	}
	c.mu.Lock()
	req, hdr := c.requests[0], c.headers[0]
	c.mu.Unlock()
	if got := hdr.Get("Authorization"); got != "Bearer t0ken" {
		t.Fatalf("Authorization header = %q", got)
	}
	if got := hdr.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	res := req.ResourceSpans[0].Resource.Attributes
	if len(res) != 1 || res[0].Key != "service.name" || res[0].Value.StringValue != "edge-waf" {
		t.Fatalf("resource attributes = %+v", res)
	}

	byName := map[string]otlpWireSpan{}
	for _, s := range spans {
		byName[s.Name] = s
	}
	r, d := byName["waf.request"], byName["detection"]
	if r.Kind != 2 || d.Kind != 1 {
		t.Fatalf("kinds: server=%d internal=%d, want 2 and 1", r.Kind, d.Kind)
	}
	if d.TraceID != r.TraceID || d.ParentSpanID != r.SpanID || r.ParentSpanID != "" {
		t.Fatalf("parentage broken: root=%+v child=%+v", r, d)
	}
	if len(r.TraceID) != 32 || len(r.SpanID) != 16 {
		t.Fatalf("ids must be hex: trace=%q span=%q", r.TraceID, r.SpanID)
	}
	if d.Status.Code != 2 || r.Status.Code != 0 {
		t.Fatalf("status codes: child=%d root=%d", d.Status.Code, r.Status.Code)
	}
	startNs, err1 := strconv.ParseInt(r.StartTimeUnixNano, 10, 64)
	endNs, err2 := strconv.ParseInt(r.EndTimeUnixNano, 10, 64)
	if err1 != nil || err2 != nil || startNs <= 0 || endNs < startNs {
		t.Fatalf("times: start=%s end=%s", r.StartTimeUnixNano, r.EndTimeUnixNano)
	}
	for _, kv := range r.Attributes {
		if kv.Key == "service.name" {
			t.Fatal("service.name must be carried on the resource, not repeated per span")
		}
	}
	if len(r.Attributes) != 1 || r.Attributes[0].Key != AttrHTTPMethod || r.Attributes[0].Value.StringValue != "GET" {
		t.Fatalf("root attributes = %+v", r.Attributes)
	}
	if len(d.Events) != 1 || d.Events[0].Name != "finding" || d.Events[0].Attributes[0].Value.StringValue != "sqli" {
		t.Fatalf("child events = %+v", d.Events)
	}
}

func TestOTLPExporterFlushesFullBatches(t *testing.T) {
	c, endpoint := newTestCollector(t)
	e, err := NewOTLPExporter(OTLPConfig{Endpoint: endpoint, BatchSize: 10, FlushInterval: time.Hour}, "svc")
	if err != nil {
		t.Fatal(err)
	}
	defer e.Shutdown()
	for range 25 {
		s := &Span{Name: "s", TraceID: strings.Repeat("a", 32), SpanID: strings.Repeat("b", 16), StartTime: time.Now()}
		s.EndTime = time.Now()
		e.Export(s)
	}
	deadline := time.Now().Add(5 * time.Second)
	for e.Sent() < 20 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if e.Sent() != 20 {
		t.Fatalf("sent %d spans before the flush interval, want two full batches (20)", e.Sent())
	}
	e.Shutdown()
	if e.Sent() != 25 || len(c.spans()) != 25 {
		t.Fatalf("after shutdown sent=%d received=%d, want 25", e.Sent(), len(c.spans()))
	}
}

// A full queue drops instead of blocking the request path.
func TestOTLPExporterDropsWhenQueueFull(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	defer srv.Close()
	defer close(block)
	e, err := NewOTLPExporter(OTLPConfig{Endpoint: srv.URL, BatchSize: 1, QueueSize: 4, Timeout: 200 * time.Millisecond, FlushInterval: time.Hour}, "")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for range 100 {
		e.Export(&Span{Name: "s", StartTime: time.Now(), EndTime: time.Now()})
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("Export blocked for %v with a stalled collector", elapsed)
	}
	if e.Dropped() < 90 {
		t.Fatalf("dropped %d spans, want at least 90 of 100 with a 4-span queue", e.Dropped())
	}
	e.Shutdown()
	if e.Sent() != 0 {
		t.Fatalf("sent %d spans to a collector that never answered", e.Sent())
	}
}

func TestOTLPExporterRetriesTransientAndDropsPermanentFailures(t *testing.T) {
	c, endpoint := newTestCollector(t)
	c.status.Store(http.StatusServiceUnavailable)
	e, err := NewOTLPExporter(OTLPConfig{Endpoint: endpoint, BatchSize: 1, FlushInterval: time.Hour}, "")
	if err != nil {
		t.Fatal(err)
	}
	e.Export(&Span{Name: "s", StartTime: time.Now(), EndTime: time.Now()})
	deadline := time.Now().Add(10 * time.Second)
	for e.Dropped() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := c.hits.Load(); got != maxOTLPRetries {
		t.Fatalf("503 was attempted %d times, want %d", got, maxOTLPRetries)
	}

	c.hits.Store(0)
	c.status.Store(http.StatusBadRequest)
	e.Export(&Span{Name: "s", StartTime: time.Now(), EndTime: time.Now()})
	for e.Dropped() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := c.hits.Load(); got != 1 {
		t.Fatalf("400 was attempted %d times, want 1 (not retryable)", got)
	}

	c.status.Store(0)
	e.Export(&Span{Name: "s", StartTime: time.Now(), EndTime: time.Now()})
	e.Shutdown()
	if e.Sent() != 1 || e.Dropped() != 2 {
		t.Fatalf("after recovery sent=%d dropped=%d, want 1 and 2", e.Sent(), e.Dropped())
	}
}

// Redirects are not followed, so configured headers never reach another origin.
func TestOTLPExporterDoesNotFollowRedirects(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
	}))
	defer other.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	e, err := NewOTLPExporter(OTLPConfig{Endpoint: redirector.URL, Headers: map[string]string{"Authorization": "Bearer x"}, FlushInterval: time.Hour}, "")
	if err != nil {
		t.Fatal(err)
	}
	e.Export(&Span{Name: "s", StartTime: time.Now(), EndTime: time.Now()})
	e.Shutdown()
	if leaked.Load() {
		t.Fatal("redirect was followed and the Authorization header leaked")
	}
	if e.Sent() != 0 || e.Dropped() != 1 {
		t.Fatalf("redirect response: sent=%d dropped=%d, want 0 and 1", e.Sent(), e.Dropped())
	}
}

// Shutdown is bounded by the request timeout even when the collector hangs.
func TestOTLPExporterShutdownIsBounded(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block }))
	defer srv.Close()
	defer close(block)
	e, err := NewOTLPExporter(OTLPConfig{Endpoint: srv.URL, Timeout: 300 * time.Millisecond, FlushInterval: time.Hour}, "")
	if err != nil {
		t.Fatal(err)
	}
	e.Export(&Span{Name: "s", StartTime: time.Now(), EndTime: time.Now()})
	start := time.Now()
	e.Shutdown()
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Shutdown took %v against a hung collector", elapsed)
	}
	e.Export(&Span{Name: "late"}) // must not panic or block after shutdown
}

func TestValidateOTLPConfig(t *testing.T) {
	valid := []OTLPConfig{
		{},
		{Endpoint: "https://otel.example.com/v1/traces"},
		{Endpoint: "http://10.0.0.5:4318/v1/traces", Headers: map[string]string{"x-honeycomb-team": "abc"}},
	}
	for _, c := range valid {
		if err := ValidateOTLPConfig(c); err != nil {
			t.Errorf("ValidateOTLPConfig(%+v) = %v, want nil", c, err)
		}
	}
	invalid := map[string]OTLPConfig{
		"scheme":       {Endpoint: "grpc://collector:4317"},
		"no host":      {Endpoint: "http:///v1/traces"},
		"userinfo":     {Endpoint: "https://user:pass@collector/v1/traces"},
		"query":        {Endpoint: "https://collector/v1/traces?x=1"},
		"header name":  {Headers: map[string]string{"bad header": "v"}},
		"header value": {Headers: map[string]string{"X-Token": "a\r\nInjected: 1"}},
		"timeout":      {Timeout: -time.Second},
		"batch":        {BatchSize: maxOTLPBatchSize + 1},
		"queue<batch":  {BatchSize: 100, QueueSize: 10},
	}
	for name, c := range invalid {
		if err := ValidateOTLPConfig(c); err == nil {
			t.Errorf("%s: ValidateOTLPConfig(%+v) = nil, want error", name, c)
		}
	}
	if err := ValidateConfig(Config{ExporterType: "otlp", OTLP: OTLPConfig{Endpoint: "ftp://x"}}); err == nil {
		t.Error("ValidateConfig must validate the OTLP block when exporter_type is otlp")
	}
}

// Reconfiguring away from OTLP flushes the old exporter and keeps the dropped
// counter monotonic.
func TestTracerReconfigureRetiresOTLPExporter(t *testing.T) {
	c, endpoint := newTestCollector(t)
	cfg := Config{Enabled: true, SamplingRate: 1, ExporterType: "otlp", OTLP: OTLPConfig{Endpoint: endpoint, FlushInterval: time.Hour}}
	tr, err := NewTracer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tr.StartSpan("before-reload", SpanKindServer).End()
	if err := tr.Reconfigure(Config{Enabled: true, SamplingRate: 1, ExporterType: "noop"}); err != nil {
		t.Fatal(err)
	}
	if got := len(c.spans()); got != 1 {
		t.Fatalf("collector received %d spans after reload, want the queued span flushed", got)
	}
	tr.Shutdown()

	c.status.Store(http.StatusBadRequest)
	tr2, err := NewTracer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tr2.StartSpan("rejected", SpanKindServer).End()
	if err := tr2.Reconfigure(cfg); err != nil {
		t.Fatal(err)
	}
	if got := tr2.DroppedSpans(); got != 1 {
		t.Fatalf("DroppedSpans after reload = %d, want 1 carried over from the retired exporter", got)
	}
	tr2.Shutdown()
}

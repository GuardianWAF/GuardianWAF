package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/tracing"
)

const (
	incomingTraceID  = "4bf92f3577b34da6a3ce929d0e0e4736"
	incomingParentID = "00f067aa0ba902b7"
	incomingHeader   = "00-" + incomingTraceID + "-" + incomingParentID + "-01"
)

func tracedEngine(t *testing.T, rate float64) (*Engine, *collectingTraceExporter) {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Tracing.Enabled = true
	cfg.Tracing.SamplingRate = rate
	cfg.Tracing.ExporterType = "noop"
	eng, _, _ := testEngineWithConfig(t, cfg)
	exporter := &collectingTraceExporter{}
	eng.tracer.SetExporter(exporter)
	return eng, exporter
}

func serveTraced(eng *Engine, traceparent string) http.Header {
	var upstream http.Header
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream = r.Header.Clone()
	})
	r := httptest.NewRequest(http.MethodGet, "/traced", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0 Safari/537.36")
	if traceparent != "" {
		r.Header.Set("traceparent", traceparent)
	}
	eng.Middleware(next).ServeHTTP(httptest.NewRecorder(), r)
	return upstream
}

func rootSpan(t *testing.T, exp *collectingTraceExporter) *tracing.Span {
	t.Helper()
	spans, _ := exp.snapshot()
	for _, s := range spans {
		if s.Name == "waf.request" {
			return s
		}
	}
	t.Fatalf("no waf.request span among %d exported", len(spans))
	return nil
}

// A sampled request joins the caller's trace, and the upstream sees the WAF
// span as its parent.
func TestTraceContextJoinsAndPropagates(t *testing.T) {
	eng, exp := tracedEngine(t, 1)
	upstream := serveTraced(eng, incomingHeader)
	root := rootSpan(t, exp)
	if root.TraceID != incomingTraceID || root.ParentID != incomingParentID {
		t.Fatalf("root span trace=%s parent=%s, want the incoming %s/%s", root.TraceID, root.ParentID, incomingTraceID, incomingParentID)
	}
	if got, want := upstream.Get("Traceparent"), tracing.FormatTraceparent(incomingTraceID, root.SpanID); got != want {
		t.Fatalf("upstream traceparent = %q, want %q", got, want)
	}
}

// Without an incoming header a new trace starts and is still propagated.
func TestTraceContextStartsNewTrace(t *testing.T) {
	eng, exp := tracedEngine(t, 1)
	upstream := serveTraced(eng, "")
	root := rootSpan(t, exp)
	if root.ParentID != "" {
		t.Fatalf("new trace has parent %q", root.ParentID)
	}
	if got := upstream.Get("Traceparent"); got != tracing.FormatTraceparent(root.TraceID, root.SpanID) {
		t.Fatalf("upstream traceparent = %q", got)
	}
}

// A malformed header is ignored (new trace) and replaced upstream.
func TestTraceContextIgnoresMalformedHeader(t *testing.T) {
	eng, exp := tracedEngine(t, 1)
	upstream := serveTraced(eng, "00-not-a-trace-01")
	root := rootSpan(t, exp)
	if root.ParentID != "" || root.TraceID == "" {
		t.Fatalf("malformed traceparent was joined: %+v", root)
	}
	if got := upstream.Get("Traceparent"); got != tracing.FormatTraceparent(root.TraceID, root.SpanID) {
		t.Fatalf("upstream traceparent = %q", got)
	}
}

// Sampling stays local: a client's sampled flag does not force a trace, and
// an unsampled request forwards the client's header untouched.
func TestTraceContextUnsampledPassesThrough(t *testing.T) {
	eng, exp := tracedEngine(t, 0)
	upstream := serveTraced(eng, incomingHeader)
	if spans, _ := exp.snapshot(); len(spans) != 0 {
		t.Fatalf("client sampled flag forced %d spans at sampling_rate 0", len(spans))
	}
	if got := upstream.Get("Traceparent"); got != incomingHeader {
		t.Fatalf("unsampled request rewrote traceparent to %q", got)
	}
}

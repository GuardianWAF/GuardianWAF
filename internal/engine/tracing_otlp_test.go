package engine

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// The configured OTLP exporter delivers the root and layer spans of a real
// request to a collector, flushed on engine close.
func TestEngineExportsSpansOverOTLP(t *testing.T) {
	var mu sync.Mutex
	var names []string
	var service string
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ResourceSpans []struct {
				Resource struct {
					Attributes []struct {
						Value struct {
							StringValue string `json:"stringValue"`
						} `json:"value"`
					} `json:"attributes"`
				} `json:"resource"`
				ScopeSpans []struct {
					Spans []struct {
						Name string `json:"name"`
					} `json:"spans"`
				} `json:"scopeSpans"`
			} `json:"resourceSpans"`
		}
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/v1/traces" || json.Unmarshal(body, &req) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		for _, rs := range req.ResourceSpans {
			service = rs.Resource.Attributes[0].Value.StringValue
			for _, ss := range rs.ScopeSpans {
				for _, s := range ss.Spans {
					names = append(names, s.Name)
				}
			}
		}
	}))
	defer collector.Close()

	cfg := config.DefaultConfig()
	cfg.Tracing.Enabled = true
	cfg.Tracing.ServiceName = "waf-otlp-test"
	cfg.Tracing.SamplingRate = 1
	cfg.Tracing.ExporterType = "otlp"
	cfg.Tracing.OTLP.Endpoint = collector.URL + "/v1/traces"
	eng, _, _ := testEngineWithConfig(t, cfg)
	eng.AddLayer(OrderedLayer{Layer: tracingTestLayer{}, Order: 100})

	eng.Check(testRequest("GET", "/traced"))
	if err := eng.Close(); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(names) != 2 || service != "waf-otlp-test" {
		t.Fatalf("collector received spans %v for service %q, want trace-test and waf.request", names, service)
	}
	if got := eng.Stats().TracingDropped; got != 0 {
		t.Fatalf("TracingDropped = %d, want 0", got)
	}
}

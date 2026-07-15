package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/tracing"
)

type responseHookLayer struct{ name string }

func (l *responseHookLayer) Name() string { return l.name }
func (l *responseHookLayer) Order() int   { return 0 }
func (l *responseHookLayer) Process(ctx *RequestContext) LayerResult {
	ctx.ResponseMaskFn = func(body string) string {
		return "masked:" + body
	}
	ctx.ClientsideBodyXform = func(body []byte, contentType string) ([]byte, bool) {
		if contentType == "text/plain; charset=utf-8" {
			return append([]byte("xform:"), body...), true
		}
		return body, false
	}
	return LayerResult{Action: ActionPass}
}

func TestMiddleware_ResponseMaskAndBodyTransform(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	e.AddLayer(OrderedLayer{Layer: &responseHookLayer{name: "response-hooks"}, Order: OrderResponse})

	handler := e.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("payload"))
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, testRequest(http.MethodGet, "/masked"))

	if got, want := rec.Body.String(), "masked:xform:payload"; got != want {
		t.Fatalf("response body = %q, want %q", got, want)
	}
	if rec.Header().Get("X-GuardianWAF-RequestID") == "" {
		t.Fatal("expected request id header to be set")
	}
}

func TestEngineReload_InvalidTrustedProxyDisablesProxyTrust(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.TrustedProxies = []string{"127.0.0.1"}
	e, _, _ := testEngineWithConfig(t, cfg)
	defer e.Close()

	req := testRequest(http.MethodGet, "/before-invalid-reload")
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	if event := e.Check(req); event.ClientIP != "203.0.113.99" {
		t.Fatalf("expected trusted proxy before reload, got %q", event.ClientIP)
	}

	reloadCfg := cfg.DeepCopy()
	reloadCfg.TrustedProxies = []string{"not-a-cidr"}
	if err := e.Reload(reloadCfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	req = testRequest(http.MethodGet, "/after-invalid-reload")
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	if event := e.Check(req); event.ClientIP != "127.0.0.1" {
		t.Fatalf("expected invalid trusted proxy config to disable trust, got %q", event.ClientIP)
	}
}

func TestExtractClientIP_PackageWrapper(t *testing.T) {
	SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.50:4321"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")

	ip := ExtractClientIP(req)
	if ip == nil || ip.String() != "198.51.100.50" {
		t.Fatalf("ExtractClientIP() = %v, want 198.51.100.50", ip)
	}
}

func TestEngineCheck_StartRootSpanWhenTracingEnabled(t *testing.T) {
	tracing.Init(tracing.Config{Enabled: true, SamplingRate: 1.0})
	defer tracing.Shutdown()

	e, _, _ := testEngine(t)
	defer e.Close()

	event := e.Check(testRequest(http.MethodGet, "/traced"))
	if event == nil {
		t.Fatal("expected non-nil event")
	}
	if event.Action != ActionPass {
		t.Fatalf("expected pass event, got %v", event.Action)
	}
}

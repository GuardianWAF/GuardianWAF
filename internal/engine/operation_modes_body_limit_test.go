package engine

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

type modeProbeLayer struct {
	name    string
	process func(*RequestContext) LayerResult
}

func (l modeProbeLayer) Name() string                            { return l.name }
func (l modeProbeLayer) Order() int                              { return OrderDetection }
func (l modeProbeLayer) Process(ctx *RequestContext) LayerResult { return l.process(ctx) }

func TestGlobalModesAndReloadPreserveApplicationResponse(t *testing.T) {
	cfg := config.DefaultConfig()
	e, store, _ := testEngineWithConfig(t, cfg)
	defer e.Close()
	calls, laterCalls, hookCalls, wsCalls := 0, 0, 0, 0
	e.AddLayer(OrderedLayer{Layer: modeProbeLayer{"block", func(ctx *RequestContext) LayerResult {
		calls++
		ctx.ResponseHook = func(http.ResponseWriter) { hookCalls++ }
		ctx.ResponseMaskFn = func(string) string { return "masked" }
		ctx.DLPBodyXform = func([]byte, string) ([]byte, bool) { return []byte("transformed"), true }
		return LayerResult{Action: ActionBlock, Findings: []Finding{{DetectorName: "probe", Score: 100}}}
	}}, Order: OrderDetection})
	e.AddLayer(OrderedLayer{Layer: modeProbeLayer{"later", func(ctx *RequestContext) LayerResult {
		laterCalls++
		return LayerResult{Action: ActionChallenge}
	}}, Order: OrderDetection + 1})
	e.SetWebSocketInterceptor(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { wsCalls++; next.ServeHTTP(w, r) })
	})
	appCalls := 0
	h := e.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appCalls++
		w.WriteHeader(201)
		_, _ = io.WriteString(w, "original")
	}))
	for _, tc := range []struct {
		mode   string
		status int
		body   string
	}{
		{"enforce", 403, ""}, {"monitor", 201, "original"}, {"disabled", 201, "original"}, {"enforce", 403, ""},
	} {
		cfg.Mode = tc.mode
		if err := e.Reload(cfg); err != nil {
			t.Fatal(err)
		}
		before, late, hook, ws := calls, laterCalls, hookCalls, wsCalls
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, testRequest("GET", "/"))
		if rr.Code != tc.status || tc.body != "" && rr.Body.String() != tc.body {
			t.Fatalf("mode %s: status=%d body=%q", tc.mode, rr.Code, rr.Body.String())
		}
		if tc.mode == "disabled" && (calls != before || laterCalls != late) {
			t.Fatal("disabled middleware ran protection layers")
		}
		if tc.mode == "monitor" && (calls != before+1 || laterCalls != late+1 || hookCalls != hook || wsCalls != ws) {
			t.Fatal("monitor did not observe all layers without response/WS enforcement")
		}
	}
	if appCalls != 2 {
		t.Fatalf("application calls=%d, want monitor and disabled only", appCalls)
	}
	if store.len() != 3 || store.get(1).Action != ActionLog {
		t.Fatal("monitor must retain a log event; disabled must not inspect/store")
	}
}

func TestGlobalModesApplyToCheckAndPayload(t *testing.T) {
	cfg := config.DefaultConfig()
	e, _, _ := testEngineWithConfig(t, cfg)
	defer e.Close()
	calls := 0
	e.AddLayer(OrderedLayer{Layer: modeProbeLayer{"block", func(ctx *RequestContext) LayerResult {
		calls++
		return LayerResult{Action: ActionBlock, Findings: []Finding{{Score: 100}}}
	}}, Order: OrderDetection})
	for _, tc := range []struct {
		mode    string
		action  Action
		blocked bool
	}{{"enforce", ActionBlock, true}, {"monitor", ActionLog, false}, {"disabled", ActionPass, false}} {
		cfg.Mode = tc.mode
		if err := e.Reload(cfg); err != nil {
			t.Fatal(err)
		}
		before := calls
		event := e.Check(testRequest("GET", "/"))
		_, blocked := e.ScanPayload("192.0.2.1", "/", "payload")
		if event.Action != tc.action || blocked != tc.blocked {
			t.Fatalf("%s: action=%s payload blocked=%v", tc.mode, event.Action, blocked)
		}
		if tc.mode == "disabled" && calls != before {
			t.Fatal("disabled Check/ScanPayload ran a layer")
		}
	}
}

func TestInspectionBodyBudgetFailsClosedAtBoundary(t *testing.T) {
	for _, mode := range []string{"enforce", "monitor", "disabled"} {
		for _, size := range []int{0, 16, 17, 40} {
			t.Run(mode+"/"+strings.Repeat("x", size), func(t *testing.T) {
				cfg := config.DefaultConfig()
				cfg.Mode = mode
				cfg.WAF.Sanitizer.MaxBodySize = 16
				e, _, _ := testEngineWithConfig(t, cfg)
				defer e.Close()
				// No sanitizer is installed: the inspection boundary must still
				// fail closed even if scoring rules or layers are disabled.
				received := -1
				h := e.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					b, err := io.ReadAll(r.Body)
					if err != nil {
						t.Fatal(err)
					}
					received = len(b)
					w.WriteHeader(204)
				}))
				r := httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("x", size)))
				if size == 40 {
					r.ContentLength = -1
				}
				rr := httptest.NewRecorder()
				h.ServeHTTP(rr, r)
				if mode == "enforce" && size > 16 {
					if rr.Code != 413 || received != -1 {
						t.Fatalf("oversized body forwarded: status=%d received=%d", rr.Code, received)
					}
				} else if rr.Code != 204 || received != size {
					t.Fatalf("body lost: status=%d received=%d", rr.Code, received)
				}
			})
		}
	}
}

func TestInspectionBudgetIncludesConfiguredLargerPaths(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Sanitizer.MaxBodySize = 16
	cfg.WAF.Sanitizer.PathOverrides = []config.PathOverride{{Path: "/upload", MaxBodySize: 64}}
	e, _, _ := testEngineWithConfig(t, cfg)
	defer e.Close()
	inspected := 0
	e.AddLayer(OrderedLayer{Layer: modeProbeLayer{"read", func(ctx *RequestContext) LayerResult {
		inspected = len(ctx.Body)
		return LayerResult{Action: ActionPass}
	}}, Order: OrderDetection})
	r := httptest.NewRequest("POST", "/upload", strings.NewReader(strings.Repeat("x", 64)))
	if event := e.Check(r); event.Action != ActionPass || inspected != 64 {
		t.Fatalf("allowed upload was truncated: action=%s inspected=%d", event.Action, inspected)
	}
}

func TestDecompressedBodyBudgetCannotBeBypassedByRatio(t *testing.T) {
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	_, _ = io.WriteString(zw, strings.Repeat("abcdefgh", 100))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.WAF.Sanitizer.MaxBodySize = 128
	e, _, _ := testEngineWithConfig(t, cfg)
	defer e.Close()
	r := httptest.NewRequest("POST", "/", bytes.NewReader(compressed.Bytes()))
	r.Header.Set("Content-Encoding", "gzip")
	event := e.Check(r)
	if event.Action != ActionBlock || event.StatusCode != 413 {
		t.Fatalf("decompressed overflow passed: %+v", event)
	}
}

type countedBody struct {
	io.ReadCloser
	reads int
}

func (b *countedBody) Read(p []byte) (int, error) {
	b.reads++
	return b.ReadCloser.Read(p)
}

func TestDisabledDoesNotReadRequestBody(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = "disabled"
	e, _, _ := testEngineWithConfig(t, cfg)
	defer e.Close()
	body := &countedBody{ReadCloser: io.NopCloser(strings.NewReader("original"))}
	r := httptest.NewRequest("POST", "/", nil)
	r.Body = body
	if event := e.Check(r); event.Action != ActionPass || body.reads != 0 {
		t.Fatalf("disabled Check inspected request: action=%s reads=%d", event.Action, body.reads)
	}
	h := e.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body.reads != 0 {
			t.Fatal("disabled middleware read body before application")
		}
		data, err := io.ReadAll(r.Body)
		if err != nil || string(data) != "original" {
			t.Fatalf("application body=%q err=%v", data, err)
		}
		w.WriteHeader(204)
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Code != 204 || rr.Header().Get("X-GuardianWAF-RequestID") != "" {
		t.Fatalf("disabled response was intercepted: %+v", rr)
	}
}

func TestMonitorLogsExplicitBlockWithoutScore(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = "monitor"
	e, store, _ := testEngineWithConfig(t, cfg)
	defer e.Close()
	e.AddLayer(OrderedLayer{Layer: modeProbeLayer{"policy", func(*RequestContext) LayerResult {
		return LayerResult{Action: ActionBlock}
	}}, Order: OrderIPACL})
	rr := httptest.NewRecorder()
	e.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rr, testRequest(http.MethodGet, "/"))
	if rr.Code != http.StatusNoContent || store.len() != 1 || store.get(0).Action != ActionLog {
		t.Fatalf("monitor must log a scoreless policy denial while forwarding: status=%d events=%+v", rr.Code, store.events)
	}
	if event := e.Check(testRequest(http.MethodGet, "/")); event.Action != ActionLog || event.Score != 0 {
		t.Fatalf("monitor Check lost scoreless denial: %+v", event)
	}
}

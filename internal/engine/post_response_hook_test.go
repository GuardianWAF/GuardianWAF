package engine

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// Regression: the engine never handed layers the upstream outcome, so
// RequestContext.PostResponseHook-style post-processing could not exist and the
// layers' PostProcess methods were unreachable in production (a successful login
// never cleared the ATO failed-attempt counter; the bot-detection error rate
// could never fire). The middleware now captures the hook before releasing the
// pooled context and invokes it once with success = upstream status < 400.
//
// hookProbeLayer registers the hook during Process and records every outcome.
type hookProbeLayer struct {
	mu       sync.Mutex
	calls    []bool
	register bool
	block    bool
}

func (l *hookProbeLayer) Name() string { return "hook-probe" }
func (l *hookProbeLayer) Order() int   { return 500 }

func (l *hookProbeLayer) Process(ctx *RequestContext) LayerResult {
	l.mu.Lock()
	register := l.register
	l.mu.Unlock()
	if register {
		ctx.PostResponseHook = func(success bool) {
			l.mu.Lock()
			l.calls = append(l.calls, success)
			l.mu.Unlock()
		}
	}
	if l.block {
		return LayerResult{Action: ActionBlock}
	}
	return LayerResult{Action: ActionPass}
}

func (l *hookProbeLayer) outcomes() []bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]bool(nil), l.calls...)
}

func (l *hookProbeLayer) setRegister(register bool) {
	l.mu.Lock()
	l.register = register
	l.mu.Unlock()
}

func serveProbe(t *testing.T, layer *hookProbeLayer, status int) *httptest.Server {
	t.Helper()
	eng, err := NewEngine(config.DefaultConfig(), newMockEventStore(), newMockEventBus())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	eng.AddLayer(OrderedLayer{Layer: layer, Order: layer.Order()})
	srv := httptest.NewServer(eng.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	})))
	t.Cleanup(srv.Close)
	return srv
}

func getProbe(t *testing.T, srv *httptest.Server) {
	t.Helper()
	resp, err := srv.Client().Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

func TestPostResponseHookReceivesUpstreamOutcome(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   bool
	}{
		{"200 is a success", http.StatusOK, true},
		{"201 is a success", http.StatusCreated, true},
		{"302 is a success", http.StatusFound, true},
		{"400 is a failure", http.StatusBadRequest, false},
		{"401 is a failure", http.StatusUnauthorized, false},
		{"403 is a failure", http.StatusForbidden, false},
		{"500 is a failure", http.StatusInternalServerError, false},
		{"503 is a failure", http.StatusServiceUnavailable, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			layer := &hookProbeLayer{register: true}
			srv := serveProbe(t, layer, tc.status)
			getProbe(t, srv)

			got := layer.outcomes()
			if len(got) != 1 {
				t.Fatalf("hook invoked %d times, want exactly 1 (%v)", len(got), got)
			}
			if got[0] != tc.want {
				t.Fatalf("hook got success=%v for upstream status %d, want %v", got[0], tc.status, tc.want)
			}
		})
	}
}

// A WAF-generated response is not an upstream outcome: the block path returns
// before the upstream call, so the hook must not fire.
func TestPostResponseHookNotInvokedWhenWAFAnswers(t *testing.T) {
	layer := &hookProbeLayer{register: true, block: true}
	srv := serveProbe(t, layer, http.StatusOK)
	getProbe(t, srv)

	if got := layer.outcomes(); len(got) != 0 {
		t.Fatalf("hook invoked %v on a WAF-blocked request; it reports upstream outcomes only", got)
	}
}

// The hook lives on the pooled context, so it must not survive into the next
// request that reuses the context.
func TestPostResponseHookNotLeakedAcrossPooledContexts(t *testing.T) {
	layer := &hookProbeLayer{register: true}
	srv := serveProbe(t, layer, http.StatusOK)

	getProbe(t, srv)
	if got := layer.outcomes(); len(got) != 1 {
		t.Fatalf("first request: hook invoked %d times, want 1", len(got))
	}

	// Second request reuses the pooled context; the layer registers nothing.
	layer.setRegister(false)
	getProbe(t, srv)
	if got := layer.outcomes(); len(got) != 1 {
		t.Fatalf("hook leaked into a request that did not register one: %v", got)
	}
}

// The status recorder sits between the handler and the real connection, so it
// must keep http.Hijacker / http.Flusher / Unwrap reachable: the WebSocket layer
// asserts Hijacker directly (internal/layers/websocket/layer.go) and the reverse
// proxy hijacks through http.ResponseController (internal/proxy/target.go).
// Installing the recorder for a layer that wants the response outcome must not
// break protocol upgrades.
func TestStatusRecorderPreservesConnectionCapabilities(t *testing.T) {
	layer := &hookProbeLayer{register: true}
	eng, err := NewEngine(config.DefaultConfig(), newMockEventStore(), newMockEventBus())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	eng.AddLayer(OrderedLayer{Layer: layer, Order: layer.Order()})

	report := make(chan string, 1)
	srv := httptest.NewServer(eng.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, ok := w.(http.Flusher); !ok {
			report <- "http.Flusher not reachable through the recorder"
			return
		}
		if u, ok := w.(interface{ Unwrap() http.ResponseWriter }); !ok || u.Unwrap() == nil {
			report <- "Unwrap not reachable through the recorder"
			return
		}
		hj, ok := w.(http.Hijacker) // the WebSocket layer's direct assertion
		if !ok {
			report <- "http.Hijacker not reachable through the recorder"
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			report <- "Hijack failed: " + err.Error()
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"))
		_ = conn.Close()
		report <- "ok"
	})))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	select {
	case got := <-report:
		if got != "ok" {
			t.Fatal(got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not report; hijack path stalled")
	}
	if string(body) != "hi" {
		t.Fatalf("hijacked response body = %q, want %q", body, "hi")
	}
}

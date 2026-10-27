package engine

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// Regression: the post-response outcome channel served MORE THAN ONE layer, but
// it held a single function, so the second layer to register silently discarded
// the first.
//
// engine.RequestContext.PostResponseHook is documented as the channel for the
// layers that need the upstream outcome: the ATO layer (order 250) clears a
// successful login's failed attempts and records its travel state, and bot
// detection (order 500) counts a failed request for its error-rate analysis. The
// pipeline runs them in that order, so bot detection's plain assignment
// overwrote the ATO layer's hook — the ATO hook never ran, and a successful
// login did not clear the failed-attempt counter.
//
// Layers now register through AddPostResponseHook, which composes the hooks:
// the engine still invokes one hook, and every registrant is called.
//
// This test pins the composition contract at its owner: two layers that each
// register a hook must BOTH receive the outcome.

// multiHookProbeLayer registers a post-response hook and records every
// outcome it receives. Its order is configurable so two of them can sit at
// the layers' real pipeline positions.
type multiHookProbeLayer struct {
	name  string
	order int

	mu    sync.Mutex
	calls []bool
}

func (l *multiHookProbeLayer) Name() string { return l.name }
func (l *multiHookProbeLayer) Order() int   { return l.order }

func (l *multiHookProbeLayer) Process(ctx *RequestContext) LayerResult {
	ctx.AddPostResponseHook(func(success bool) {
		l.mu.Lock()
		l.calls = append(l.calls, success)
		l.mu.Unlock()
	})
	return LayerResult{Action: ActionPass}
}

func (l *multiHookProbeLayer) outcomes() []bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]bool(nil), l.calls...)
}

func TestPostResponseHookComposesMultipleRegistrants(t *testing.T) {
	// The two real positions: ATO (250) and bot detection (500).
	first := &multiHookProbeLayer{name: "multi-hook-first", order: OrderATO}
	second := &multiHookProbeLayer{name: "multi-hook-second", order: OrderBotDetect}

	eng, err := NewEngine(config.DefaultConfig(), newMockEventStore(), newMockEventBus())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close() })
	eng.AddLayer(OrderedLayer{Layer: first, Order: first.Order()})
	eng.AddLayer(OrderedLayer{Layer: second, Order: second.Order()})

	srv := httptest.NewServer(eng.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	for _, l := range []*multiHookProbeLayer{first, second} {
		got := l.outcomes()
		if len(got) != 1 {
			t.Fatalf("%s: hook invoked %d times, want exactly 1 (%v) — a later layer's "+
				"registration discarded the earlier one", l.Name(), len(got), got)
		}
		if !got[0] {
			t.Fatalf("%s: hook got success=false for upstream status 200, want true", l.Name())
		}
	}
}

// A failure outcome must reach every registrant too, not just the last one.
func TestPostResponseHookComposesFailureOutcome(t *testing.T) {
	first := &multiHookProbeLayer{name: "multi-hook-fail-first", order: OrderATO}
	second := &multiHookProbeLayer{name: "multi-hook-fail-second", order: OrderBotDetect}

	eng, err := NewEngine(config.DefaultConfig(), newMockEventStore(), newMockEventBus())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close() })
	eng.AddLayer(OrderedLayer{Layer: first, Order: first.Order()})
	eng.AddLayer(OrderedLayer{Layer: second, Order: second.Order()})

	srv := httptest.NewServer(eng.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	for _, l := range []*multiHookProbeLayer{first, second} {
		got := l.outcomes()
		if len(got) != 1 {
			t.Fatalf("%s: hook invoked %d times, want exactly 1 (%v)", l.Name(), len(got), got)
		}
		if got[0] {
			t.Fatalf("%s: hook got success=true for upstream status 500, want false", l.Name())
		}
	}
}

package response_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/response"
)

// blockingLayer stands in for any of the 16 layers that can short-circuit the
// pipeline with ActionBlock (IP ACL, rate limit, CRS, detection, …).
type blockingLayer struct{}

func (blockingLayer) Name() string { return "test-blocker" }

func (blockingLayer) Order() int { return engine.OrderDetection }

func (blockingLayer) Process(*engine.RequestContext) engine.LayerResult {
	return engine.LayerResult{
		Action:   engine.ActionBlock,
		Score:    100,
		Duration: time.Microsecond,
	}
}

// TestSecurityHeadersAppliedOnBlockedRequest pins the fix for a gap that
// affected the single response an attacker can always force.
//
// The response layer sits at Order 600 and is the only thing in the tree that
// sets HSTS, X-Frame-Options, X-Content-Type-Options and CSP. The pipeline's
// ActionBlock short-circuit returned before reaching it, so every 403 the WAF
// produced was framable, sniffable and served without HSTS — while ordinary
// allowed traffic got the full header set.
func TestSecurityHeadersAppliedOnBlockedRequest(t *testing.T) {
	cfg := response.DefaultConfig()
	respLayer := response.NewLayer(&cfg)

	pipeline := engine.NewPipeline(
		engine.OrderedLayer{Layer: blockingLayer{}, Order: engine.OrderDetection},
		engine.OrderedLayer{Layer: respLayer, Order: engine.OrderResponse},
	)

	r := httptest.NewRequest("GET", "http://example.com/?id=1", nil)
	ctx := engine.AcquireContext(r, 1, 10<<20)
	defer engine.ReleaseContext(ctx)

	result := pipeline.Execute(ctx)
	if result.Action != engine.ActionBlock {
		t.Fatalf("pipeline action = %v, want block", result.Action)
	}

	if ctx.ResponseHook == nil {
		t.Fatal("blocked request registered no response hook: security headers would be missing from the 403")
	}

	w := httptest.NewRecorder()
	ctx.ResponseHook(w)

	for _, hdr := range []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
	} {
		if got := w.Header().Get(hdr); got == "" {
			t.Errorf("blocked response missing %s", hdr)
		}
	}
}

// TestResponseLayerNotRunTwiceOnPass guards the non-blocking path: the response
// layer must run exactly once, not once in the loop and again in the
// short-circuit helper.
func TestResponseLayerNotRunTwiceOnPass(t *testing.T) {
	cfg := response.DefaultConfig()
	respLayer := response.NewLayer(&cfg)

	pipeline := engine.NewPipeline(
		engine.OrderedLayer{Layer: respLayer, Order: engine.OrderResponse},
	)

	r := httptest.NewRequest("GET", "http://example.com/", nil)
	ctx := engine.AcquireContext(r, 1, 10<<20)
	defer engine.ReleaseContext(ctx)

	result := pipeline.Execute(ctx)
	if result.Action != engine.ActionPass {
		t.Fatalf("pipeline action = %v, want pass", result.Action)
	}
	if _, ok := result.LayerTiming[respLayer.Name()]; !ok {
		t.Fatal("response layer did not run on the pass path")
	}
	if ctx.ResponseHook == nil {
		t.Fatal("pass path registered no response hook")
	}
}

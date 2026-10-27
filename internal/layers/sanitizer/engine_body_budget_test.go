package sanitizer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

type discardEvents struct{}

func (discardEvents) Store(engine.Event) error { return nil }
func (discardEvents) Close() error             { return nil }

type discardBus struct{}

func (discardBus) Subscribe(chan<- engine.Event) {}
func (discardBus) Publish(engine.Event)          {}
func (discardBus) Close()                        {}

type inspectionProbe struct{ size *int }

func (inspectionProbe) Name() string { return "probe" }
func (inspectionProbe) Order() int   { return 1 }
func (p inspectionProbe) Process(ctx *engine.RequestContext) engine.LayerResult {
	*p.size = len(ctx.Body)
	return engine.LayerResult{Action: engine.ActionPass}
}

func TestEngineUsesEffectiveSanitizerLimitBeforeReading(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Sanitizer.MaxBodySize = 8
	cfg.WAF.Sanitizer.PathOverrides = []config.PathOverride{{Path: "/upload", MaxBodySize: 32}, {Path: "/admin", MaxBodySize: 4}}
	e, err := engine.NewEngine(cfg, discardEvents{}, discardBus{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	layer := NewLayer(&Config{MaxBodySize: 8, PathOverrides: []PathOverride{{Path: "/upload", MaxBodySize: 32}, {Path: "/admin", MaxBodySize: 4}}})
	e.AddLayer(engine.OrderedLayer{Layer: layer, Order: engine.OrderSanitizer})
	inspected := 0
	e.AddLayer(engine.OrderedLayer{Layer: inspectionProbe{&inspected}, Order: 1})
	for _, tc := range []struct {
		path        string
		size, limit int
		blocked     bool
		tenant      bool
	}{
		{"/plain", 8, 8, false, false}, {"/plain", 9, 8, true, false},
		{"/upload", 32, 32, false, false}, {"/x/../upload", 32, 32, false, false}, {"/upload", 33, 32, true, false},
		{"/admin", 5, 4, true, false}, {"/plain", 4, 3, true, true},
	} {
		r := httptest.NewRequest("POST", tc.path, strings.NewReader(strings.Repeat("x", tc.size)))
		if tc.tenant {
			tenantCfg := cfg.WAF
			tenantCfg.Sanitizer.MaxBodySize = 3
			r = r.WithContext(engine.WithTenantContext(context.Background(), &engine.TenantContext{WAFConfig: &tenantCfg}))
		}
		event := e.Check(r)
		if (event.Action == engine.ActionBlock) != tc.blocked || inspected != min(tc.size, tc.limit+1) {
			t.Fatalf("%s size%d tenant%v action=%s inspected=%d, want blocked=%v budget=%d", tc.path, tc.size, tc.tenant, event.Action, inspected, tc.blocked, tc.limit)
		}
	}
	// Middleware and dry-run must agree at the hard limit.
	rr := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/plain", strings.NewReader("123456789"))
	e.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("oversized body forwarded") })).ServeHTTP(rr, r)
	if rr.Code != 413 {
		t.Fatalf("status=%d, want413", rr.Code)
	}
}

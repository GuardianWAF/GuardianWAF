package dashboard

// Regression: the rate-limit config PUT was a dead end — validateRuntimeReloadableConfig
//
// Defect: handleUpdateRateLimitConfig (internal/dashboard/config_subresource_handlers.go)
// decodes, validates, applies to a config copy, and calls engine.Reload —
// which is runtime-only — but never invokes routingCtrl.Save (whose SaveFn
// closure writes config.SaveFile(cfgPath, eng.Config()), the full current
// engine config). Rate-limit settings are therefore runtime-only: a restart
// silently reverts them to the stale config file, disarming the DoS defense
// the operator just configured. Third instance of the runtime-only config
// class proven in rounds 73 (apivalidation) and 74 (CRS).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

type round75MockEventStore struct{}

func (round75MockEventStore) Store(event engine.Event) error { return nil }
func (round75MockEventStore) Close() error                   { return nil }

type round75MockEventBus struct{}

func (round75MockEventBus) Subscribe(ch chan<- engine.Event) {}
func (round75MockEventBus) Publish(event engine.Event)       {}
func (round75MockEventBus) Close()                           {}

func TestRateLimitConfigUpdate(t *testing.T) {
	cfg := config.DefaultConfig()
	e, err := engine.NewEngine(cfg, round75MockEventStore{}, round75MockEventBus{})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	d := &Dashboard{engine: e}

	saved := false
	d.SetRoutingController(AtomicRoutingControllerFuncs{
		RoutingControllerFuncs: RoutingControllerFuncs{
			SaveFn: func() error {
				saved = true
				return nil
			},
		},
	})

	putReq := httptest.NewRequest("PUT", "/api/v1/config/ratelimit",
		strings.NewReader(`{"enabled":true,"default_limit":10,"window":"1m","burst":20,"action":"block"}`))
	putRec := httptest.NewRecorder()
	d.handleUpdateRateLimitConfig(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("FAIL: rate-limit config PUT is a dead end — status %d body %s; validateRuntimeReloadableConfig 409s the handler's own primary fields (the rate-limit rules are part of the WAF shape guard) while the sibling CRS and API-validation handlers apply the same class of change through engine.Reload's pipeline rebuild", putRec.Code, putRec.Body.String())
	}

	if !saved {
		t.Fatalf("FAIL: PUT reported ok but nothing was persisted — routingCtrl.Save was never invoked; rate-limit settings are runtime-only and a restart will silently revert enabled/default_limit/burst/action to the stale config file, disarming the DoS defense the operator just configured")
	}
}

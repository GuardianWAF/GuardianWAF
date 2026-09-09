package dashboard

// Regression: the bot-detection config PUT was a validator dead-end —
//
// Defect: handleUpdateBotConfig calls validateRuntimeReloadableConfig, whose
// guard 409s any WAF-shape diff except two atomic-exempt fields — the
// bot-detection settings are part of the WAF shape, so every CHANGING update
// (enabled flip, mode change, threshold change) returns 409 "runtime reload
// cannot change WAF layer configuration... update the config file and
// restart", while the sibling CRS, API-validation, and rate-limit handlers
// apply the same class of change through engine.Reload's pipeline rebuild.
// It also never persists (routingCtrl.Save writes the full live engine
// config), so even after the guard is removed the settings would be
// runtime-only. Same class as the round-75 rate-limit fix.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

type round76MockEventStore struct{}

func (round76MockEventStore) Store(event engine.Event) error { return nil }
func (round76MockEventStore) Close() error                   { return nil }

type round76MockEventBus struct{}

func (round76MockEventBus) Subscribe(ch chan<- engine.Event) {}
func (round76MockEventBus) Publish(event engine.Event)       {}
func (round76MockEventBus) Close()                           {}

func TestBotConfigUpdateWorksAndPersists(t *testing.T) {
	cfg := config.DefaultConfig()
	e, err := engine.NewEngine(cfg, round76MockEventStore{}, round76MockEventBus{})
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

	// A CHANGING bot body: enabled:false flips the layer flag (the default
	// is enabled), which the validator's topology guard 409s today.
	putReq := httptest.NewRequest("PUT", "/api/v1/config/bot",
		strings.NewReader(`{"enabled":false,"mode":"block"}`))
	putRec := httptest.NewRecorder()
	d.handleUpdateBotConfig(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("FAIL: bot config PUT is a dead end — status %d body %s; validateRuntimeReloadableConfig 409s the handler's own primary fields (the bot-detection settings are part of the WAF shape guard) while the sibling CRS, API-validation, and rate-limit handlers apply the same class of change through engine.Reload's pipeline rebuild", putRec.Code, putRec.Body.String())
	}

	if !saved {
		t.Fatalf("FAIL: PUT reported ok but nothing was persisted — routingCtrl.Save was never invoked; bot-detection settings are runtime-only and a restart will silently restore the bot posture the operator just changed")
	}
}

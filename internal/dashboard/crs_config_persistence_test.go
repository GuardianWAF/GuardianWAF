package dashboard

// Regression: handleConfig PUT (CRS settings) reloaded the engine but never persisted
//
// Defect: handleConfig's PUT (CRS settings) reloads the engine — a runtime-only
// operation — but never invokes routingCtrl.Save, whose SaveFn closure writes
// config.SaveFile(cfgPath, eng.Config()) (the FULL current engine config,
// runtime mutations included). CRS settings are therefore runtime-only: a
// restart silently reverts paranoia_level/anomaly_threshold/enabled to the
// last value written to the config file, restoring whatever the operator
// believed they had changed. Same class as the round-73 API-validation
// persistence defect; same canonical fix (the handleUpdateConfig contract).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

type round74MockEventStore struct{}

func (round74MockEventStore) Store(event engine.Event) error { return nil }
func (round74MockEventStore) Close() error                   { return nil }

type round74MockEventBus struct{}

func (round74MockEventBus) Subscribe(ch chan<- engine.Event) {}
func (round74MockEventBus) Publish(event engine.Event)       {}
func (round74MockEventBus) Close()                           {}

func TestCRSConfigPersists(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.CRS.Enabled = true
	e, err := engine.NewEngine(cfg, round74MockEventStore{}, round74MockEventBus{})
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

	h := NewCRSHandler(d)

	putReq := httptest.NewRequest("PUT", "/api/crs/config",
		strings.NewReader(`{"enabled":true,"paranoia_level":2,"anomaly_threshold":10}`))
	putRec := httptest.NewRecorder()
	h.handleConfig(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT: status %d body %s", putRec.Code, putRec.Body.String())
	}

	if !saved {
		t.Fatalf("FAIL: PUT reported updated but nothing was persisted — routingCtrl.Save was never invoked; CRS settings are runtime-only and a restart will silently revert paranoia_level, anomaly_threshold, and enabled to the stale config file")
	}
}

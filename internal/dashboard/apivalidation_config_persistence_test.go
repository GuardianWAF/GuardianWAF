package dashboard

// Regression: handleValidationConfig PUT reloaded the engine but never persisted
//
// Defect: handleValidationConfig's PUT calls engine.Reload but never
// routingCtrl.Save(), so API-validation settings are runtime-only. The Save
// closure in cmd/guardianwaf writes the ENTIRE engine config
// (config.SaveFile(cfgPath, eng.Config())), and handleUpdateConfig uses it as
// its persistence step — but this handler does not. An operator enabling
// block_on_violation gets 200 OK, and the next restart silently reverts it.
import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/apivalidation"
)

func TestAPIValidationConfigPersists(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.APIValidation.Enabled = true
	e, err := engine.NewEngine(cfg, round73MockEventStore{}, round73MockEventBus{})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	layer := apivalidation.NewLayer(&apivalidation.Config{Enabled: true})
	d := &Dashboard{
		engine:                e,
		apiValidationOverride: &apiValidationAdapter{layer: layer},
	}

	saved := false
	d.SetRoutingController(AtomicRoutingControllerFuncs{
		RoutingControllerFuncs: RoutingControllerFuncs{
			SaveFn: func() error {
				saved = true
				return nil
			},
		},
	})

	h := NewAPIValidationHandler(d)

	putReq := httptest.NewRequest("PUT", "/api/apivalidation/config",
		strings.NewReader(`{"enabled":true,"validate_request":true,"validate_response":true,"strict_mode":true,"block_on_violation":true}`))
	putRec := httptest.NewRecorder()
	h.handleValidationConfig(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT: status %d body %s", putRec.Code, putRec.Body.String())
	}

	if !saved {
		t.Fatalf("FAIL: PUT reported updated but nothing was persisted — routingCtrl.Save was never invoked; API-validation settings are runtime-only and a restart will silently revert block_on_violation")
	}
}

type round73MockEventStore struct{}

func (round73MockEventStore) Store(event engine.Event) error { return nil }
func (round73MockEventStore) Close() error                   { return nil }

type round73MockEventBus struct{}

func (round73MockEventBus) Subscribe(ch chan<- engine.Event) {}
func (round73MockEventBus) Publish(event engine.Event)       {}
func (round73MockEventBus) Close()                           {}

package dashboard

// Regression: handleConfig PUT (client-side settings) reloaded the engine but never persisted.
//
// Defect: handleConfig's PUT (/api/clientside/config) reloaded the engine — a
// runtime-only operation — but never invoked routingCtrl.Save, so mode /
// magecart_detection / agent_injection / CSP settings were runtime-only: a
// restart silently reverted the operator's bot-protection posture to the last
// config-file state. Same class as the round-74 CRS persistence defect; same
// canonical fix (oldCfg snapshot, Save with fail-rollback — the
// handleUpdateConfig contract shared by every config-mutating PUT).
//
// Mirrors crs_config_persistence_test.go (round-74 twin).

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

type csCfgMockEventStore struct{}

func (csCfgMockEventStore) Store(event engine.Event) error { return nil }
func (csCfgMockEventStore) Close() error                   { return nil }

type csCfgMockEventBus struct{}

func (csCfgMockEventBus) Subscribe(ch chan<- engine.Event) {}
func (csCfgMockEventBus) Publish(event engine.Event)       {}
func (csCfgMockEventBus) Close()                           {}

// newClientSideConfigTestDashboard wires a Dashboard + engine whose
// routingCtrl.Save records invocation and returns saveErr.
func newClientSideConfigTestDashboard(t *testing.T, saveErr error) (*Dashboard, *engine.Engine, *bool) {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.WAF.ClientSide.Enabled = true
	e, err := engine.NewEngine(cfg, csCfgMockEventStore{}, csCfgMockEventBus{})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	d := &Dashboard{engine: e}

	saved := false
	d.SetRoutingController(AtomicRoutingControllerFuncs{
		RoutingControllerFuncs: RoutingControllerFuncs{
			SaveFn: func() error {
				saved = true
				return saveErr
			},
		},
	})
	return d, e, &saved
}

func TestClientSideConfigPersists(t *testing.T) {
	d, e, saved := newClientSideConfigTestDashboard(t, nil)
	h := NewClientSideHandler(d)

	putReq := httptest.NewRequest("PUT", "/api/clientside/config",
		strings.NewReader(`{"mode":"strict","csp_enabled":true}`))
	putRec := httptest.NewRecorder()
	h.handleConfig(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT: status %d body %s", putRec.Code, putRec.Body.String())
	}

	// The runtime posture must actually have changed (proves the PUT reached
	// engine.Reload — the persistence gap is the only failure under test).
	if got := e.Config().WAF.ClientSide.CSP.Enabled; !got {
		t.Fatalf("runtime config not updated by PUT (unexpected; harness broken)")
	}

	if !*saved {
		t.Fatalf("FAIL: PUT reported updated but nothing was persisted — routingCtrl.Save was never invoked; client-side mode/Magecart/agent/CSP settings are runtime-only and a restart will silently revert the operator's posture to the stale config file")
	}
}

func TestClientSideConfigSaveFailureRollsBack(t *testing.T) {
	d, e, _ := newClientSideConfigTestDashboard(t, errors.New("disk full"))
	before := e.Config().WAF.ClientSide
	h := NewClientSideHandler(d)

	putReq := httptest.NewRequest("PUT", "/api/clientside/config",
		strings.NewReader(`{"mode":"strict","csp_enabled":true}`))
	putRec := httptest.NewRecorder()
	h.handleConfig(putRec, putReq)

	if putRec.Code != http.StatusInternalServerError {
		t.Fatalf("PUT with failing Save: status %d body %s (want 500)", putRec.Code, putRec.Body.String())
	}

	// The rollback contract must restore the operator's prior posture.
	after := e.Config().WAF.ClientSide
	if after.CSP.Enabled {
		t.Fatalf("rollback: CSP.Enabled still true after persistence failure — the prior posture was not restored")
	}
	if after.Mode != before.Mode {
		t.Fatalf("rollback: Mode %q != pre-update %q", after.Mode, before.Mode)
	}
}

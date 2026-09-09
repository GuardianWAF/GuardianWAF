package dashboard

// Regression: the CRS config PUT accepted any paranoia/anomaly integers.
//
// Defect: handleConfig PUT accepts any ParanoiaLevel int. layer.go:189 skips
// rules with rule.ParanoiaLevel > config.ParanoiaLevel, and CRS rules are
// minimum PL-1 — so paranoia_level: 0 gates out EVERY rule while the handler
// returns 200 OK. The CRS silently stops evaluating.

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

type round66MockEventStore struct{}

func (round66MockEventStore) Store(event engine.Event) error { return nil }
func (round66MockEventStore) Close() error                   { return nil }

type round66MockEventBus struct{}

func (round66MockEventBus) Subscribe(ch chan<- engine.Event) {}
func (round66MockEventBus) Publish(event engine.Event)       {}
func (round66MockEventBus) Close()                           {}

func TestCRSConfigRejectsParanoiaOutsideSpec(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.CRS.Enabled = true
	cfg.WAF.CRS.ParanoiaLevel = 1
	cfg.WAF.CRS.AnomalyThreshold = 5

	e, err := engine.NewEngine(cfg, round66MockEventStore{}, round66MockEventBus{})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	d := &Dashboard{engine: e}
	h := NewCRSHandler(d)

	req := httptest.NewRequest("PUT", "/api/crs/config",
		strings.NewReader(`{"enabled":true,"paranoia_level":0,"anomaly_threshold":5}`))
	rec := httptest.NewRecorder()
	h.handleConfig(rec, req)

	got := d.engine.Config().WAF.CRS.ParanoiaLevel
	if got == 0 {
		t.Fatalf("FAIL: paranoia_level=0 accepted with HTTP %d — layer.go:189 gates out every rule (minimum PL-1) and the CRS silently stops evaluating", rec.Code)
	}
}

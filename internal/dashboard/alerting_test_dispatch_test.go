package dashboard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression: handleTestAlert was a self-disclosed stub that answered
// {status:"ok"} for every target while the alerting manager's real
// TestAlert(targetName) existed and the dashboard already consumed the
// manager for stats. Fixed: the handler delegates through an injected seam;
// unwired deployments get an honest 501 and manager failures are relayed as
// 502 instead of being manufactured into success.

type alertingTestDispatchProvider struct{ err error }

func (p alertingTestDispatchProvider) TestAlert(targetName string) error {
	return p.err
}

func TestAlertingTestDispatchUnwired(t *testing.T) {
	cfg := config.DefaultConfig()
	e, err := engine.NewEngine(cfg, alertingTestDispatchMockEventStore{}, alertingTestDispatchMockEventBus{})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	d := &Dashboard{engine: e}

	req := httptest.NewRequest("POST", "/api/v1/alerting/test", strings.NewReader(`{"target":"nope"}`))
	rec := httptest.NewRecorder()
	d.handleTestAlert(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for unwired alerting test, got %d body %s", rec.Code, rec.Body.String())
	}
}

func TestAlertingTestDispatchRelaysManagerFailure(t *testing.T) {
	cfg := config.DefaultConfig()
	e, err := engine.NewEngine(cfg, alertingTestDispatchMockEventStore{}, alertingTestDispatchMockEventBus{})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	d := &Dashboard{engine: e}
	d.SetAlertingTestFn(alertingTestDispatchProvider{err: errors.New("connection refused")}.TestAlert)

	req := httptest.NewRequest("POST", "/api/v1/alerting/test", strings.NewReader(`{"target":"webhook1"}`))
	rec := httptest.NewRecorder()
	d.handleTestAlert(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 when the alerting manager reports failure, got %d body %s", rec.Code, rec.Body.String())
	}
}

type alertingTestDispatchMockEventStore struct{}

func (alertingTestDispatchMockEventStore) Store(event engine.Event) error { return nil }
func (alertingTestDispatchMockEventStore) Close() error                   { return nil }

type alertingTestDispatchMockEventBus struct{}

func (alertingTestDispatchMockEventBus) Subscribe(ch chan<- engine.Event) {}
func (alertingTestDispatchMockEventBus) Publish(event engine.Event)       {}
func (alertingTestDispatchMockEventBus) Close()                           {}

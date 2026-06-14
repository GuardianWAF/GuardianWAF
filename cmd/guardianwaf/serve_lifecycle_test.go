package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/acme"
	"github.com/guardianwaf/guardianwaf/internal/config"
	dkr "github.com/guardianwaf/guardianwaf/internal/docker"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
)

type stoppableThreatIntelLayer struct {
	cleanupTestLayer
	stopped atomic.Int32
}

type contextStoppableThreatIntelLayer struct {
	cleanupTestLayer
	stopped atomic.Int32
}

type fakeACMERenewal struct {
	stopped atomic.Int32
}

type fakeContextACMERenewal struct {
	stopped        atomic.Int32
	contextStopped atomic.Int32
}

type fakeTenantManager struct {
	closed atomic.Int32
}

type fakeGeoIPRefreshStopper struct {
	stopped atomic.Int32
}

func (f *fakeACMERenewal) StopRenewal() {
	f.stopped.Add(1)
}

func (f *fakeContextACMERenewal) StopRenewal() {
	f.stopped.Add(1)
}

func (f *fakeContextACMERenewal) StopRenewalWithContext(context.Context) error {
	f.contextStopped.Add(1)
	return nil
}

func (f *fakeTenantManager) CloseWithContext(context.Context) error {
	f.closed.Add(1)
	return nil
}

func (f *fakeGeoIPRefreshStopper) StopWithContext(context.Context) error {
	f.stopped.Add(1)
	return nil
}

func (l *stoppableThreatIntelLayer) Stop() {
	l.stopped.Add(1)
}

func (l *contextStoppableThreatIntelLayer) StopWithContext(context.Context) error {
	l.stopped.Add(1)
	return nil
}

func TestCloseStopChannelIsIdempotent(t *testing.T) {
	ch := make(chan struct{})
	closeStopChannel(ch)
	closeStopChannel(ch)

	select {
	case <-ch:
	default:
		t.Fatal("expected channel to be closed")
	}
}

func TestCloseStopChannelNil(t *testing.T) {
	closeStopChannel(nil)
}

func TestStopThreatIntelCallsLayerStop(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	layer := &stoppableThreatIntelLayer{
		cleanupTestLayer: cleanupTestLayer{name: "threat_intel"},
	}
	eng.AddLayer(engine.OrderedLayer{Layer: layer, Order: engine.OrderThreatIntel})

	stopEngineLayer(context.Background(), eng, "threat_intel", "Threat intel")
	if layer.stopped.Load() != 1 {
		t.Fatalf("expected threat intel Stop to be called once, got %d", layer.stopped.Load())
	}
}

func TestStopThreatIntelPrefersContextStop(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	layer := &contextStoppableThreatIntelLayer{
		cleanupTestLayer: cleanupTestLayer{name: "threat_intel"},
	}
	eng.AddLayer(engine.OrderedLayer{Layer: layer, Order: engine.OrderThreatIntel})

	stopEngineLayer(context.Background(), eng, "threat_intel", "Threat intel")
	if layer.stopped.Load() != 1 {
		t.Fatalf("expected threat intel StopWithContext to be called once, got %d", layer.stopped.Load())
	}
}

func TestStopEngineLayerStopsVirtualPatchWithContext(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	layer := &contextStoppableThreatIntelLayer{
		cleanupTestLayer: cleanupTestLayer{name: "virtualpatch"},
	}
	eng.AddLayer(engine.OrderedLayer{Layer: layer, Order: engine.OrderVirtualPatch})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stopEngineLayer(ctx, eng, "virtualpatch", "Virtual patch")
	if layer.stopped.Load() != 1 {
		t.Fatalf("expected virtual patch StopWithContext to be called once, got %d", layer.stopped.Load())
	}
}

func TestStopEngineLayerStopsIPACLWithContext(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	layer := &contextStoppableThreatIntelLayer{
		cleanupTestLayer: cleanupTestLayer{name: "ipacl"},
	}
	eng.AddLayer(engine.OrderedLayer{Layer: layer, Order: engine.OrderIPACL})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stopEngineLayer(ctx, eng, "ipacl", "IP ACL")
	if layer.stopped.Load() != 1 {
		t.Fatalf("expected ipacl StopWithContext to be called once, got %d", layer.stopped.Load())
	}
}

func TestShutdownServeRuntimeStopsACMERenewal(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	renewal := &fakeACMERenewal{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	shutdownServeRuntime(ctx, serveShutdownResources{
		engine:      eng,
		acmeRenewal: renewal,
	})

	if got := renewal.stopped.Load(); got != 1 {
		t.Fatalf("StopRenewal calls = %d, want 1", got)
	}
}

func TestShutdownServeRuntimePrefersACMERenewalContextStop(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	renewal := &fakeContextACMERenewal{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	shutdownServeRuntime(ctx, serveShutdownResources{
		engine:      eng,
		acmeRenewal: renewal,
	})

	if got := renewal.contextStopped.Load(); got != 1 {
		t.Fatalf("StopRenewalWithContext calls = %d, want 1", got)
	}
	if got := renewal.stopped.Load(); got != 0 {
		t.Fatalf("StopRenewal calls = %d, want 0 when context stop is available", got)
	}
}

func TestShutdownServeRuntimeClosesTenantManagerWithContext(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	tenantMgr := &fakeTenantManager{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	shutdownServeRuntime(ctx, serveShutdownResources{
		engine:        eng,
		tenantManager: tenantMgr,
	})

	if got := tenantMgr.closed.Load(); got != 1 {
		t.Fatalf("Tenant manager CloseWithContext calls = %d, want 1", got)
	}
}

func TestShutdownServeRuntimeStopsGeoIPRefreshWithContext(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	refresh := &fakeGeoIPRefreshStopper{}
	layerResources := &layerRuntimeResources{}
	layerResources.addGeoIPRefresh(refresh)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	shutdownServeRuntime(ctx, serveShutdownResources{
		engine:         eng,
		layerResources: layerResources,
	})

	if got := refresh.stopped.Load(); got != 1 {
		t.Fatalf("GeoIP StopWithContext calls = %d, want 1", got)
	}
	if err := layerResources.stopGeoIPRefresh(context.Background()); err != nil {
		t.Fatalf("second GeoIP stop returned error: %v", err)
	}
	if got := refresh.stopped.Load(); got != 1 {
		t.Fatalf("GeoIP StopWithContext calls after second stop = %d, want 1", got)
	}
}

func TestShutdownServeRuntimeStopsIPACLWithContext(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	layer := &contextStoppableThreatIntelLayer{
		cleanupTestLayer: cleanupTestLayer{name: "ipacl"},
	}
	eng.AddLayer(engine.OrderedLayer{Layer: layer, Order: engine.OrderIPACL})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	shutdownServeRuntime(ctx, serveShutdownResources{
		engine: eng,
	})

	if got := layer.stopped.Load(); got != 1 {
		t.Fatalf("IP ACL StopWithContext calls = %d, want 1", got)
	}
}

func TestShutdownSidecarRuntimeStopsIPACLWithContext(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	layer := &contextStoppableThreatIntelLayer{
		cleanupTestLayer: cleanupTestLayer{name: "ipacl"},
	}
	eng.AddLayer(engine.OrderedLayer{Layer: layer, Order: engine.OrderIPACL})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	shutdownSidecarRuntime(ctx, sidecarShutdownResources{
		engine: eng,
	})

	if got := layer.stopped.Load(); got != 1 {
		t.Fatalf("IP ACL StopWithContext calls = %d, want 1", got)
	}
}

func TestShutdownSidecarRuntimeStopsGeoIPRefreshWithContext(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	refresh := &fakeGeoIPRefreshStopper{}
	layerResources := &layerRuntimeResources{}
	layerResources.addGeoIPRefresh(refresh)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	shutdownSidecarRuntime(ctx, sidecarShutdownResources{
		engine:         eng,
		layerResources: layerResources,
	})

	if got := refresh.stopped.Load(); got != 1 {
		t.Fatalf("GeoIP StopWithContext calls = %d, want 1", got)
	}
}

func TestShutdownServeRuntimeStopsDockerWatcherWithContext(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	watcher := dkr.NewWatcher(dkr.NewClient(""), "gwaf", "bridge", time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	shutdownServeRuntime(ctx, serveShutdownResources{
		engine:        eng,
		dockerWatcher: watcher,
	})

	if watcher.Stats().EventStreamConnected {
		t.Fatal("expected docker watcher event stream to be disconnected during shutdown")
	}
}

func TestShutdownServeRuntimeIgnoresNilACMERenewalPointer(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	var renewal *acme.CertDiskStore
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	shutdownServeRuntime(ctx, serveShutdownResources{
		engine:      eng,
		acmeRenewal: renewal,
	})
}

func TestShutdownServeRuntimeClosesProxyRouter(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}

	target, err := proxy.NewTargetWithPolicy("http://127.0.0.1:18081", 1, proxy.TargetPolicy{AllowPrivateTargets: true})
	if err != nil {
		t.Fatalf("NewTargetWithPolicy: %v", err)
	}
	router := proxy.NewRouter([]proxy.Route{{
		PathPrefix: "/",
		Balancer:   proxy.NewBalancer([]*proxy.Target{target}, proxy.StrategyRoundRobin),
	}})
	checkers := []*proxy.HealthChecker{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	shutdownServeRuntime(ctx, serveShutdownResources{
		engine:              eng,
		proxyRouter:         &router,
		proxyHealthCheckers: &checkers,
	})

	if router != nil {
		t.Fatal("expected proxy router pointer to be cleared during shutdown")
	}
	if checkers != nil {
		t.Fatal("expected proxy health checkers to be cleared during shutdown")
	}
	if !target.Closed() {
		t.Fatal("expected proxy target to be closed during shutdown")
	}
}

func TestShutdownSidecarRuntimeClosesProxyRouterAndStopsCleanup(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}

	target, err := proxy.NewTargetWithPolicy("http://127.0.0.1:18082", 1, proxy.TargetPolicy{AllowPrivateTargets: true})
	if err != nil {
		t.Fatalf("NewTargetWithPolicy: %v", err)
	}
	router := proxy.NewRouter([]proxy.Route{{
		PathPrefix: "/",
		Balancer:   proxy.NewBalancer([]*proxy.Target{target}, proxy.StrategyRoundRobin),
	}})
	checkers := []*proxy.HealthChecker{}
	cleanupStop, cleanupWG := startPeriodicCleanup(eng, nil, time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	shutdownSidecarRuntime(ctx, sidecarShutdownResources{
		engine:              eng,
		proxyRouter:         &router,
		proxyHealthCheckers: &checkers,
		cleanupStop:         cleanupStop,
		cleanupWG:           cleanupWG,
	})

	if router != nil {
		t.Fatal("expected sidecar proxy router pointer to be cleared during shutdown")
	}
	if checkers != nil {
		t.Fatal("expected sidecar proxy health checkers to be cleared during shutdown")
	}
	if !target.Closed() {
		t.Fatal("expected sidecar proxy target to be closed during shutdown")
	}
	select {
	case <-cleanupStop:
	default:
		t.Fatal("expected sidecar cleanup stop channel to be closed during shutdown")
	}
}

func TestLogServeRuntimeStatus(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.Listen = "127.0.0.1:0"
	cfg.WAF.Challenge.Enabled = true
	cfg.WAF.BotDetection.Enabled = true
	cfg.VirtualHosts = []config.VirtualHostConfig{{Domains: []string{"example.com"}}}

	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	logServeRuntimeStatus(cfg, eng)
}

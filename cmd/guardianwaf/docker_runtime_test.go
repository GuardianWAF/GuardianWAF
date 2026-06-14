package main

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	dkr "github.com/guardianwaf/guardianwaf/internal/docker"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
)

func TestSetupDockerRuntimeDisabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Docker.Enabled = false

	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	var upstream atomic.Value
	upstream.Store(http.NotFoundHandler())
	var proxyRouter *proxy.Router
	var proxyHealthCheckers []*proxy.HealthChecker
	var proxyRuntimeMu sync.RWMutex

	if watcher := setupDockerRuntime(cfg, eng, nil, &proxyRouter, &proxyHealthCheckers, &proxyRuntimeMu, &upstream, nil); watcher != nil {
		t.Fatalf("expected nil watcher when Docker is disabled, got %v", watcher)
	}
	if loadHTTPHandler(&upstream) == nil {
		t.Fatal("disabled Docker runtime removed the upstream handler")
	}
	if proxyRouter != nil {
		t.Fatal("disabled Docker runtime changed proxy router")
	}
}

func TestRebuildDockerProxyRuntimeInstallsDiscoveredRouter(t *testing.T) {
	cfg := config.DefaultConfig()
	allowPrivate := true
	cfg.AllowPrivateUpstreams = &allowPrivate
	cfg.Upstreams = nil
	cfg.Routes = nil
	cfg.VirtualHosts = nil

	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	var upstream atomic.Value
	upstream.Store(http.NotFoundHandler())
	oldTarget, err := proxy.NewTargetWithPolicy("http://127.0.0.1:18079", 1, proxy.TargetPolicy{AllowPrivateTargets: true})
	if err != nil {
		t.Fatalf("NewTargetWithPolicy: %v", err)
	}
	proxyRouter := proxy.NewRouter([]proxy.Route{{
		PathPrefix: "/",
		Balancer:   proxy.NewBalancer([]*proxy.Target{oldTarget}, proxy.StrategyRoundRobin),
	}})
	var proxyHealthCheckers []*proxy.HealthChecker
	var proxyRuntimeMu sync.RWMutex

	rebuildDockerProxyRuntime(
		cfg,
		eng,
		nil,
		[]dkr.DiscoveredService{{
			ContainerID:   "abc123",
			ContainerName: "backend",
			IPAddress:     "127.0.0.1",
			Port:          18080,
			Path:          "/",
			Weight:        1,
			LBStrategy:    "round_robin",
			UpstreamName:  "backend",
			Status:        "running",
		}},
		&proxyRouter,
		&proxyHealthCheckers,
		&proxyRuntimeMu,
		&upstream,
		nil,
	)

	if proxyRouter == nil {
		t.Fatal("expected discovered Docker services to install a proxy router")
	}
	if len(proxyHealthCheckers) != 0 {
		t.Fatalf("expected no health checkers without Docker health labels, got %d", len(proxyHealthCheckers))
	}
	if loadHTTPHandler(&upstream) == nil {
		t.Fatal("expected upstream handler to be atomically replaced")
	}
	if !oldTarget.Closed() {
		t.Fatal("expected old Docker proxy target to be closed after rebuild")
	}
}

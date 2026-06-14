package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/dashboard"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/rules"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
)

func TestSyncCustomRulesToConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer eng.Close()

	rLayer := rules.NewLayer(&rules.Config{Enabled: true}, nil)
	rLayer.AddRule(rules.Rule{
		ID:       "r1",
		Name:     "test rule",
		Enabled:  true,
		Priority: 7,
		Conditions: []rules.Condition{
			{Field: "path", Op: "contains", Value: "/admin"},
		},
		Action: "block",
		Score:  80,
	})
	eng.AddLayer(engine.OrderedLayer{Layer: rLayer, Order: engine.OrderRules})

	syncCustomRulesToConfig(eng, cfg)

	if !cfg.WAF.CustomRules.Enabled {
		t.Fatal("expected custom rules to be enabled")
	}
	if got := len(cfg.WAF.CustomRules.Rules); got != 1 {
		t.Fatalf("expected 1 custom rule, got %d", got)
	}
	synced := cfg.WAF.CustomRules.Rules[0]
	if synced.ID != "r1" || synced.Name != "test rule" || synced.Action != "block" || synced.Score != 80 {
		t.Fatalf("unexpected synced rule: %+v", synced)
	}
	if got := len(synced.Conditions); got != 1 {
		t.Fatalf("expected 1 condition, got %d", got)
	}
	if synced.Conditions[0].Field != "path" || synced.Conditions[0].Op != "contains" || synced.Conditions[0].Value != "/admin" {
		t.Fatalf("unexpected synced condition: %+v", synced.Conditions[0])
	}
}

func TestLoadHTTPHandler(t *testing.T) {
	var value atomic.Value
	if got := loadHTTPHandler(&value); got != nil {
		t.Fatalf("expected nil handler before store, got %#v", got)
	}

	handler := http.NotFoundHandler()
	value.Store(handler)
	if got := loadHTTPHandler(&value); got == nil {
		t.Fatal("expected stored handler")
	}
}

func TestDashboardRoutingRebuildUsesReloadedConfigAndDrainsActiveTraffic(t *testing.T) {
	releaseOld := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			close(releaseOld)
		})
	}
	defer release()

	oldStarted := make(chan struct{}, 1)
	oldBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case oldStarted <- struct{}{}:
		default:
		}
		<-releaseOld
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("old-drained"))
	}))
	defer oldBackend.Close()

	newBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("new-route"))
	}))
	defer newBackend.Close()

	allowPrivate := true
	cfg := config.DefaultConfig()
	cfg.AllowPrivateUpstreams = &allowPrivate
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.APIKey = "routing-test-key"
	cfg.Upstreams = []config.UpstreamConfig{{
		Name: "default",
		Targets: []config.TargetConfig{{
			URL:    oldBackend.URL,
			Weight: 1,
		}},
		HealthCheck: config.HealthCheckConfig{Enabled: false},
	}}
	cfg.Routes = []config.RouteConfig{{Path: "/", Upstream: "default"}}

	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer eng.Close()

	dash := dashboard.New(eng, events.NewMemoryStore(10), "routing-test-key")
	oldTarget, err := proxy.NewTargetWithPolicy(oldBackend.URL, 1, proxy.TargetPolicy{AllowPrivateTargets: true})
	if err != nil {
		t.Fatalf("NewTargetWithPolicy: %v", err)
	}
	proxyRouter := proxy.NewRouter([]proxy.Route{{
		PathPrefix: "/",
		Balancer:   proxy.NewBalancer([]*proxy.Target{oldTarget}, proxy.StrategyRoundRobin),
	}})
	proxyHandler := http.Handler(proxyRouter)
	var proxyHealthCheckers []*proxy.HealthChecker

	var proxyRuntimeMu sync.RWMutex
	var upstreamHandler atomic.Value
	upstreamHandler.Store(eng.Middleware(proxyHandler))
	cfgPath := filepath.Join(t.TempDir(), "guardianwaf.yaml")
	wireDashboardProxyControls(
		dash,
		cfg,
		eng,
		cfgPath,
		&proxyRouter,
		&proxyHealthCheckers,
		&proxyRuntimeMu,
		&upstreamHandler,
		nil,
	)

	oldRespCh := make(chan string, 1)
	oldErrCh := make(chan error, 1)
	go func() {
		req := httptest.NewRequest(http.MethodGet, "/slow", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0")
		rec := httptest.NewRecorder()
		loadHTTPHandler(&upstreamHandler).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			oldErrCh <- errStatus(rec.Code)
			return
		}
		oldRespCh <- rec.Body.String()
	}()

	select {
	case <-oldStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("old in-flight request did not reach old backend")
	}

	updateBody := []byte(`{
		"upstreams": [
			{"name": "default", "targets": [{"url": "` + newBackend.URL + `", "weight": 1}]}
		],
		"routes": [
			{"path": "/", "upstream": "default"}
		]
	}`)
	updateReq := httptest.NewRequest(http.MethodPut, "/api/v1/routing", bytes.NewReader(updateBody))
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.Header.Set("X-API-Key", "routing-test-key")
	updateRec := httptest.NewRecorder()
	dash.Handler().ServeHTTP(updateRec, updateReq)
	if updateRec.Code != http.StatusOK {
		t.Fatalf("routing update status = %d, body = %s", updateRec.Code, updateRec.Body.String())
	}
	if !oldTarget.Closed() {
		t.Fatal("expected old dashboard proxy target to be closed after rebuild")
	}

	newReq := httptest.NewRequest(http.MethodGet, "/after-rebuild", nil)
	newReq.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0")
	newRec := httptest.NewRecorder()
	loadHTTPHandler(&upstreamHandler).ServeHTTP(newRec, newReq)
	if newRec.Code != http.StatusOK {
		t.Fatalf("new route status = %d, body = %s", newRec.Code, newRec.Body.String())
	}
	if body := newRec.Body.String(); body != "new-route" {
		t.Fatalf("new route body = %q, want %q", body, "new-route")
	}

	release()
	select {
	case err := <-oldErrCh:
		t.Fatalf("old in-flight request failed after rebuild: %v", err)
	case body := <-oldRespCh:
		if body != "old-drained" {
			t.Fatalf("old in-flight body = %q, want %q", body, "old-drained")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("old in-flight request did not drain after rebuild")
	}
}

type errStatus int

func (e errStatus) Error() string {
	return fmt.Sprintf("unexpected status %d", e)
}

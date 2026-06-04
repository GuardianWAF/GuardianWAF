package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
)

func allowPrivateUpstreamsForTest(cfg *config.Config) {
	allowPrivate := true
	cfg.AllowPrivateUpstreams = &allowPrivate
}

func TestBuildProxyRuntime_UsesFallbackWithoutRoutes(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstreams = nil
	cfg.Routes = nil
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "fallback")
	})

	handler, router, checkers := buildProxyRuntime(cfg, fallback)

	if router != nil {
		t.Fatal("expected nil router when no upstreams/routes are configured")
	}
	if len(checkers) != 0 {
		t.Fatalf("expected no health checkers, got %d", len(checkers))
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rr.Body.String(); got != "fallback" {
		t.Fatalf("expected fallback body %q, got %q", "fallback", got)
	}
}

func TestBuildProxyRuntime_BuildsRouterWithConfiguredRoute(t *testing.T) {
	cfg := config.DefaultConfig()
	allowPrivateUpstreamsForTest(cfg)
	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name: "default",
			Targets: []config.TargetConfig{
				{URL: "http://127.0.0.1:1", Weight: 1},
			},
		},
	}
	cfg.Routes = []config.RouteConfig{{Path: "/", Upstream: "default"}}

	handler, router, checkers := buildProxyRuntime(cfg, http.NotFoundHandler())

	if handler == nil {
		t.Fatal("expected handler")
	}
	if router == nil {
		t.Fatal("expected router")
	}
	if len(checkers) != 0 {
		t.Fatalf("expected no health checkers, got %d", len(checkers))
	}

}

func TestBuildReverseProxy_ResetsPrivateTargetAllowance(t *testing.T) {
	cfg := config.DefaultConfig()
	allowPrivateUpstreamsForTest(cfg)
	cfg.Upstreams = []config.UpstreamConfig{{
		Name:    "default",
		Targets: []config.TargetConfig{{URL: "http://127.0.0.1:1", Weight: 1}},
	}}
	cfg.Routes = []config.RouteConfig{{Path: "/", Upstream: "default"}}

	buildReverseProxy(cfg)
	if !proxy.PrivateTargetsAllowed() {
		t.Fatal("expected private targets to be allowed after explicit true config")
	}

	cfg.AllowPrivateUpstreams = nil
	cfg.Upstreams = nil
	cfg.Routes = nil
	buildReverseProxy(cfg)
	if proxy.PrivateTargetsAllowed() {
		t.Fatal("expected private target allowance to reset when config is not explicit")
	}
}

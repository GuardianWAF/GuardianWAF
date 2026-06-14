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

func TestBuildProxyRuntime_BuildsRouterWithVirtualHostOnlyRoutes(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "vhost-ok")
	}))
	defer backend.Close()

	cfg := config.DefaultConfig()
	allowPrivateUpstreamsForTest(cfg)
	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name: "vhost",
			Targets: []config.TargetConfig{
				{URL: backend.URL, Weight: 1},
			},
		},
	}
	cfg.Routes = nil
	cfg.VirtualHosts = []config.VirtualHostConfig{
		{
			Domains: []string{"api.example.test"},
			Routes:  []config.RouteConfig{{Path: "/", Upstream: "vhost"}},
		},
	}

	handler, router, checkers := buildProxyRuntime(cfg, http.NotFoundHandler())
	defer stopHealthCheckers(checkers)

	if handler == nil {
		t.Fatal("expected handler")
	}
	if router == nil {
		t.Fatal("expected router for virtual-host-only routes")
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://api.example.test/", nil)
	req.Host = "api.example.test"
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Body.String(); got != "vhost-ok" {
		t.Fatalf("expected vhost backend response, got %q", got)
	}
}

func TestStandaloneProxyPathHonorsTrustedProxyClientIPModel(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "backend-ok")
	}))
	defer backend.Close()

	for _, tc := range []struct {
		name           string
		trustedProxies []string
		remoteAddr     string
		xff            string
		wantClientIP   string
	}{
		{
			name:         "untrusted direct peer cannot spoof x-forwarded-for",
			remoteAddr:   "127.0.0.1:12345",
			xff:          "203.0.113.10",
			wantClientIP: "127.0.0.1",
		},
		{
			name:           "trusted proxy chain selects rightmost non-trusted hop",
			trustedProxies: []string{"127.0.0.1/32"},
			remoteAddr:     "127.0.0.1:12345",
			xff:            "203.0.113.10, 198.51.100.20, 127.0.0.1",
			wantClientIP:   "198.51.100.20",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			allowPrivateUpstreamsForTest(cfg)
			cfg.TrustedProxies = tc.trustedProxies
			cfg.WAF.Detection.Threshold.Block = 1000
			cfg.WAF.Detection.Threshold.Log = 1000
			cfg.Upstreams = []config.UpstreamConfig{{
				Name: "default",
				Targets: []config.TargetConfig{
					{URL: backend.URL, Weight: 1},
				},
			}}
			cfg.Routes = []config.RouteConfig{{Path: "/", Upstream: "default"}}

			store, _, eng, _, err := setupRuntimeEngine(cfg)
			if err != nil {
				t.Fatalf("setupRuntimeEngine: %v", err)
			}
			t.Cleanup(func() { _ = eng.Close() })

			upstream, router, checkers := buildProxyRuntime(cfg, standaloneNoUpstreamHandler())
			t.Cleanup(func() {
				stopHealthCheckers(checkers)
				closeProxyRouter(router)
			})

			req := httptest.NewRequest(http.MethodGet, "http://waf.example.test/", nil)
			req.RemoteAddr = tc.remoteAddr
			req.Header.Set("X-Forwarded-For", tc.xff)
			rr := httptest.NewRecorder()

			eng.Middleware(upstream).ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("expected proxied 200 response, got %d: %s", rr.Code, rr.Body.String())
			}
			if got := rr.Body.String(); got != "backend-ok" {
				t.Fatalf("expected backend response, got %q", got)
			}

			events, err := store.Recent(1)
			if err != nil {
				t.Fatalf("recent events: %v", err)
			}
			if len(events) != 1 {
				t.Fatalf("expected one stored event, got %d", len(events))
			}
			if events[0].ClientIP != tc.wantClientIP {
				t.Fatalf("event client_ip = %q, want %q", events[0].ClientIP, tc.wantClientIP)
			}
		})
	}
}

func TestBuildReverseProxy_DoesNotMutateGlobalPrivateTargetAllowance(t *testing.T) {
	proxy.SetPrivateTargetsAllowed(false)

	cfg := config.DefaultConfig()
	allowPrivateUpstreamsForTest(cfg)
	cfg.Upstreams = []config.UpstreamConfig{{
		Name:    "default",
		Targets: []config.TargetConfig{{URL: "http://127.0.0.1:1", Weight: 1}},
	}}
	cfg.Routes = []config.RouteConfig{{Path: "/", Upstream: "default"}}

	buildReverseProxy(cfg)
	if proxy.PrivateTargetsAllowed() {
		t.Fatal("expected runtime proxy assembly not to mutate global private target allowance")
	}
	if _, err := proxy.NewTarget("http://127.0.0.1:1", 1); err == nil {
		t.Fatal("expected global NewTarget to still block private target")
	}
}

func TestBuildReverseProxy_UsesAllowedUpstreamCIDRs(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AllowedUpstreamCIDRs = []string{"127.0.0.1/32"}
	cfg.Upstreams = []config.UpstreamConfig{{
		Name:    "default",
		Targets: []config.TargetConfig{{URL: "http://127.0.0.1:1", Weight: 1}},
	}}
	cfg.Routes = []config.RouteConfig{{Path: "/", Upstream: "default"}}

	handler, checkers := buildReverseProxy(cfg)
	defer stopHealthCheckers(checkers)

	if handler == nil {
		t.Fatal("expected handler")
	}

	proxy.SetPrivateTargetsAllowed(false)
	if err := proxy.SetAllowedUpstreamCIDRs(nil); err != nil {
		t.Fatalf("SetAllowedUpstreamCIDRs(nil) error = %v", err)
	}
	if _, err := proxy.NewTarget("http://127.0.0.1:1", 1); err == nil {
		t.Fatal("expected global NewTarget to still block private target")
	}
}

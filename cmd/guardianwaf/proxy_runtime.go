package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
)

// buildReverseProxy creates an http.Handler that routes requests to upstreams
// based on the configured routes. It uses the proxy package for load balancing
// and health checking across multiple targets per upstream.
func buildReverseProxy(cfg *config.Config) (http.Handler, []*proxy.HealthChecker) {
	handler, healthCheckers, _ := buildReverseProxyWithMode(cfg, false)
	return handler, healthCheckers
}

// buildReverseProxyStrict builds a complete candidate router or returns an
// error without leaving health checkers or target transports running. Runtime
// reload paths use this before swapping the active handler so an invalid or
// newly-private DNS result cannot silently produce a partial router.
func buildReverseProxyStrict(cfg *config.Config) (http.Handler, []*proxy.HealthChecker, error) {
	return buildReverseProxyWithMode(cfg, true)
}

func buildReverseProxyWithMode(cfg *config.Config, strict bool) (http.Handler, []*proxy.HealthChecker, error) {
	targetPolicy := proxy.TargetPolicy{
		AllowPrivateTargets: cfg.AllowPrivateUpstreams != nil && *cfg.AllowPrivateUpstreams,
	}
	allowedCIDRs, err := proxy.ParseAllowedUpstreamCIDRs(cfg.AllowedUpstreamCIDRs)
	if err != nil {
		if strict {
			return nil, nil, fmt.Errorf("invalid upstream CIDR allowlist: %w", err)
		}
		slog.Warn("invalid upstream CIDR allowlist", "error", err)
	} else {
		targetPolicy.AllowedCIDRs = allowedCIDRs
	}

	// Build balancers: name -> *Balancer
	balancerMap := make(map[string]*proxy.Balancer)
	var healthCheckers []*proxy.HealthChecker
	var builtTargets []*proxy.Target
	cleanupCandidate := func() {
		stopHealthCheckers(healthCheckers)
		for _, target := range builtTargets {
			target.Close()
		}
	}

	for _, u := range cfg.Upstreams {
		var targets []*proxy.Target
		for _, t := range u.Targets {
			target, err := proxy.NewTargetWithPolicy(t.URL, t.Weight, targetPolicy)
			if err != nil {
				if strict {
					cleanupCandidate()
					return nil, nil, fmt.Errorf("upstream %q target %q: %w", u.Name, t.URL, err)
				}
				slog.Warn("invalid upstream URL", "url", t.URL, "error", err)
				continue
			}
			targets = append(targets, target)
			builtTargets = append(builtTargets, target)
		}
		if len(targets) == 0 {
			continue
		}

		strategy := u.LoadBalancer
		if strategy == "" {
			strategy = proxy.StrategyRoundRobin
		}
		lb := proxy.NewBalancer(targets, strategy)
		balancerMap[u.Name] = lb

		// Start health checks if configured
		if u.HealthCheck.Enabled {
			hc := proxy.NewHealthChecker(lb, proxy.HealthConfig{
				Enabled:  true,
				Interval: u.HealthCheck.Interval,
				Timeout:  u.HealthCheck.Timeout,
				Path:     u.HealthCheck.Path,
			})
			hc.Start()
			healthCheckers = append(healthCheckers, hc)
		}
	}

	// Build default routes (flat routes array - fallback)
	defaultRoutes := make([]proxy.Route, 0, len(cfg.Routes))
	for _, route := range cfg.Routes {
		lb, ok := balancerMap[route.Upstream]
		if !ok {
			continue
		}
		defaultRoutes = append(defaultRoutes, proxy.Route{
			PathPrefix:  route.Path,
			Balancer:    lb,
			StripPrefix: route.StripPrefix,
		})
	}

	// Build virtual hosts if configured
	if len(cfg.VirtualHosts) > 0 {
		var vhosts []proxy.VirtualHost
		for _, vh := range cfg.VirtualHosts {
			var vhRoutes []proxy.Route
			for _, route := range vh.Routes {
				lb, ok := balancerMap[route.Upstream]
				if !ok {
					continue
				}
				vhRoutes = append(vhRoutes, proxy.Route{
					PathPrefix:  route.Path,
					Balancer:    lb,
					StripPrefix: route.StripPrefix,
				})
			}
			vhosts = append(vhosts, proxy.VirtualHost{
				Domains: vh.Domains,
				Routes:  vhRoutes,
			})
		}
		return proxy.NewRouterWithVHosts(vhosts, defaultRoutes), healthCheckers, nil
	}

	return proxy.NewRouter(defaultRoutes), healthCheckers, nil
}

func buildProxyRuntime(cfg *config.Config, fallback http.Handler) (http.Handler, *proxy.Router, []*proxy.HealthChecker) {
	if !proxyRoutingConfigured(cfg) {
		return fallback, nil, nil
	}

	handler, healthCheckers := buildReverseProxy(cfg)
	router, _ := handler.(*proxy.Router)
	return handler, router, healthCheckers
}

func proxyRoutingConfigured(cfg *config.Config) bool {
	if cfg == nil || len(cfg.Upstreams) == 0 {
		return false
	}
	if len(cfg.Routes) > 0 {
		return true
	}
	for _, vh := range cfg.VirtualHosts {
		if len(vh.Routes) > 0 {
			return true
		}
	}
	return false
}

func standaloneNoUpstreamHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "GuardianWAF is running. No upstream configured.")
	})
}

func sidecarNoUpstreamHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintln(w, "502 Bad Gateway - No upstream configured")
	})
}

func stopHealthCheckers(checkers []*proxy.HealthChecker) {
	_ = stopHealthCheckersWithContext(context.Background(), checkers)
}

func stopHealthCheckersWithContext(ctx context.Context, checkers []*proxy.HealthChecker) error {
	var stopErr error
	for _, hc := range checkers {
		if hc != nil {
			if err := hc.StopWithContext(ctx); err != nil && stopErr == nil {
				stopErr = err
			}
		}
	}
	return stopErr
}

func closeProxyRouter(router *proxy.Router) {
	if router != nil {
		router.Close()
	}
}

func waitForWaitGroup(ctx context.Context, wg *sync.WaitGroup) error {
	if wg == nil {
		return nil
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

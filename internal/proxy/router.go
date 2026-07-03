package proxy

import (
	"bytes"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/guardianwaf/guardianwaf/internal/netutil"
)

const maxRetries = 2

// maxRetryBodyBytes bounds how large a request body may be to buffer it for
// cross-target failover retries. Bodies larger than this are proxied once
// (streamed) without retry, so a large upload cannot be buffered into memory.
const maxRetryBodyBytes = 1 << 20 // 1 MiB

// Route maps a path prefix to a load balancer with optional prefix stripping.
type Route struct {
	PathPrefix  string
	Balancer    *Balancer
	StripPrefix bool
}

// VirtualHost groups routes under one or more domain names.
type VirtualHost struct {
	Domains []string
	Routes  []Route
}

// Router dispatches requests based on Host header (virtual hosts) and path prefix.
// If no virtual host matches the request's Host, the default routes are used.
type Router struct {
	mu            sync.RWMutex
	exactHosts    map[string]*vhostEntry // "api.example.com" -> entry
	wildcardHosts []wildcardEntry        // sorted by suffix length desc
	defaultRoutes []Route                // fallback when no vhost matches
}

type vhostEntry struct {
	routes []Route
}

type wildcardEntry struct {
	suffix string // ".example.com" (without leading *)
	routes []Route
}

// NewRouter creates a router with default routes (no virtual hosts).
func NewRouter(routes []Route) *Router {
	return &Router{
		exactHosts:    make(map[string]*vhostEntry),
		defaultRoutes: sortRoutes(routes),
	}
}

// NewRouterWithVHosts creates a router with virtual hosts and default fallback routes.
func NewRouterWithVHosts(vhosts []VirtualHost, defaultRoutes []Route) *Router {
	rt := &Router{
		exactHosts:    make(map[string]*vhostEntry),
		defaultRoutes: sortRoutes(defaultRoutes),
	}

	for _, vh := range vhosts {
		entry := &vhostEntry{routes: sortRoutes(vh.Routes)}
		for _, domain := range vh.Domains {
			if strings.HasPrefix(domain, "*.") {
				suffix := domain[1:] // "*.example.com" -> ".example.com"
				rt.wildcardHosts = append(rt.wildcardHosts, wildcardEntry{
					suffix: suffix,
					routes: entry.routes,
				})
			} else {
				rt.exactHosts[strings.ToLower(domain)] = entry
			}
		}
	}

	// Sort wildcards by suffix length desc (most specific first)
	sort.Slice(rt.wildcardHosts, func(i, j int) bool {
		return len(rt.wildcardHosts[i].suffix) > len(rt.wildcardHosts[j].suffix)
	})

	return rt
}

// ServeHTTP finds the matching virtual host and route, then proxies.
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	routes := rt.lookupRoutes(r.Host)

	// Normalize path before matching — prevents bypasses via //, /../, etc.
	reqPath := path.Clean(r.URL.Path)

	for _, route := range routes {
		if !strings.HasPrefix(reqPath, route.PathPrefix) {
			continue
		}
		// Apply normalized path to the request so downstream uses the clean path
		r.URL.Path = reqPath
		target := route.Balancer.Next(r)
		if target == nil {
			http.Error(w, "503 Service Unavailable - No healthy backends", http.StatusServiceUnavailable)
			return
		}

		stripPrefix := ""
		if route.StripPrefix {
			stripPrefix = route.PathPrefix
		}

		// Buffer a bounded request body so a cross-target retry can replay it —
		// the first attempt drains r.Body, so without this a failover would send
		// an empty body upstream. Oversized/unknown-length bodies are streamed
		// once without retry rather than buffered into memory.
		var replayBody []byte
		canReplayBody := false
		if route.Balancer.Len() > 1 && r.Body != nil && r.Body != http.NoBody &&
			r.ContentLength >= 0 && r.ContentLength <= maxRetryBodyBytes {
			buf, err := io.ReadAll(io.LimitReader(r.Body, maxRetryBodyBytes))
			_ = r.Body.Close()
			if err == nil {
				replayBody = buf
				canReplayBody = true
				r.Body = io.NopCloser(bytes.NewReader(replayBody))
			} else {
				// Reading failed; give downstream an empty body rather than a
				// half-consumed stream.
				r.Body = io.NopCloser(bytes.NewReader(nil))
			}
		}

		// Send to first target; retry on proxy error (502) if more targets exist.
		proxyErr := target.ServeHTTP(w, r, stripPrefix)
		if proxyErr == nil || route.Balancer.Len() <= 1 {
			return
		}

		// Retry with different targets (skip ones already tried in this request)
		tried := map[string]bool{target.URL.String(): true}
		for attempt := 0; attempt < maxRetries; attempt++ {
			next := route.Balancer.Next(r)
			if next == nil {
				break
			}
			nextURL := next.URL.String()
			if tried[nextURL] {
				continue // skip already-tried target
			}
			tried[nextURL] = true
			// Replay the buffered body for this attempt (the previous attempt
			// consumed the reader).
			if canReplayBody {
				r.Body = io.NopCloser(bytes.NewReader(replayBody))
			}
			if next.ServeHTTP(w, r, stripPrefix) == nil {
				return
			}
		}
		// All attempts failed — send 502 to client
		http.Error(w, "502 Bad Gateway", http.StatusBadGateway)
		return
	}

	http.Error(w, "404 Not Found - No route matched", http.StatusNotFound)
}

// lookupRoutes resolves Host header to a route list.
// Priority: exact match > wildcard match > default routes.
func (rt *Router) lookupRoutes(host string) []Route {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	// Strip port from host
	h := stripPort(host)
	h = strings.ToLower(h)

	// 1. Exact match
	if entry, ok := rt.exactHosts[h]; ok {
		return entry.routes
	}

	// 2. Wildcard match (*.example.com matches sub.example.com)
	for _, wc := range rt.wildcardHosts {
		if strings.HasSuffix(h, wc.suffix) {
			return wc.routes
		}
	}

	// 3. Default routes
	return rt.defaultRoutes
}

// UpstreamStatus describes the health of a balancer's targets.
type UpstreamStatus struct {
	Name         string         `json:"name"`
	Strategy     string         `json:"strategy"`
	Targets      []TargetStatus `json:"targets"`
	HealthyCount int            `json:"healthy_count"`
	TotalCount   int            `json:"total_count"`
}

// TargetStatus describes a single target's current state.
type TargetStatus struct {
	URL          string `json:"url"`
	Healthy      bool   `json:"healthy"`
	CircuitState string `json:"circuit_state"`
	ActiveConns  int64  `json:"active_conns"`
	Weight       int    `json:"weight"`
}

// AllUpstreamStatus returns the status of all unique balancers across all routes.
func (rt *Router) AllUpstreamStatus() []UpstreamStatus {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	seen := make(map[*Balancer]bool)
	var result []UpstreamStatus

	collectBalancers := func(routes []Route) {
		for _, route := range routes {
			if route.Balancer == nil || seen[route.Balancer] {
				continue
			}
			seen[route.Balancer] = true

			targets := route.Balancer.Targets()
			ts := make([]TargetStatus, len(targets))
			healthyCount := 0
			for i, t := range targets {
				healthy := t.IsHealthy()
				if healthy {
					healthyCount++
				}
				ts[i] = TargetStatus{
					URL:          t.URL.String(),
					Healthy:      healthy,
					CircuitState: t.CircuitState().String(),
					ActiveConns:  t.ActiveConns(),
					Weight:       t.Weight,
				}
			}
			result = append(result, UpstreamStatus{
				Name:         route.PathPrefix,
				Strategy:     route.Balancer.Strategy(),
				Targets:      ts,
				HealthyCount: healthyCount,
				TotalCount:   len(targets),
			})
		}
	}

	// Default routes
	collectBalancers(rt.defaultRoutes)

	// Vhost routes
	for _, entry := range rt.exactHosts {
		collectBalancers(entry.routes)
	}
	for _, wc := range rt.wildcardHosts {
		collectBalancers(wc.routes)
	}

	return result
}

// Close releases idle connections held by every unique target reachable from
// the router. It is intended for route reload and shutdown cleanup.
func (rt *Router) Close() {
	if rt == nil {
		return
	}

	rt.mu.RLock()
	defer rt.mu.RUnlock()

	seenBalancers := make(map[*Balancer]bool)
	seenTargets := make(map[*Target]bool)

	closeRoutes := func(routes []Route) {
		for _, route := range routes {
			if route.Balancer == nil || seenBalancers[route.Balancer] {
				continue
			}
			seenBalancers[route.Balancer] = true
			for _, target := range route.Balancer.Targets() {
				if target == nil || seenTargets[target] {
					continue
				}
				seenTargets[target] = true
				target.Close()
			}
		}
	}

	closeRoutes(rt.defaultRoutes)
	for _, entry := range rt.exactHosts {
		closeRoutes(entry.routes)
	}
	for _, wc := range rt.wildcardHosts {
		closeRoutes(wc.routes)
	}
}

// sortRoutes returns a copy sorted by path prefix length desc (longest first).
func sortRoutes(routes []Route) []Route {
	sorted := make([]Route, len(routes))
	copy(sorted, routes)
	sort.Slice(sorted, func(i, j int) bool {
		return len(sorted[i].PathPrefix) > len(sorted[j].PathPrefix)
	})
	return sorted
}

// stripPort removes the port suffix from a host string.
func stripPort(host string) string {
	return netutil.StripPort(host)
}

package proxy

import (
	"net/http"
	"sort"
	"strings"
	"sync"
)

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

	for _, route := range routes {
		if strings.HasPrefix(r.URL.Path, route.PathPrefix) {
			target := route.Balancer.Next(r)
			if target == nil {
				http.Error(w, "503 Service Unavailable - No healthy backends", http.StatusServiceUnavailable)
				return
			}

			stripPrefix := ""
			if route.StripPrefix {
				stripPrefix = route.PathPrefix
			}
			target.ServeHTTP(w, r, stripPrefix)
			return
		}
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
	idx := strings.LastIndex(host, ":")
	if idx < 0 {
		return host
	}
	// IPv6: [::1]:8088
	if strings.Contains(host, "]") {
		bracket := strings.LastIndex(host, "]")
		if idx > bracket {
			return host[:idx]
		}
		return host
	}
	return host[:idx]
}

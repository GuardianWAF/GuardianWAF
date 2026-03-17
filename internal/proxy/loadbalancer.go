package proxy

import (
	"hash/fnv"
	"math/rand/v2"
	"net/http"
	"sync/atomic"
)

// LoadBalancer selects a backend for a given request.
type LoadBalancer interface {
	Select(r *http.Request) *Backend
}

// NewLoadBalancer creates a load balancer with the specified algorithm.
func NewLoadBalancer(algorithm string, backends []*Backend) LoadBalancer {
	switch algorithm {
	case "weighted":
		return NewWeighted(backends)
	case "least_conn":
		return NewLeastConn(backends)
	case "ip_hash":
		return NewIPHash(backends)
	default:
		return NewRoundRobin(backends)
	}
}

// --- Round Robin ---

// RoundRobin selects backends in circular order.
type RoundRobin struct {
	backends []*Backend
	counter  atomic.Uint64
}

// NewRoundRobin creates a new round-robin load balancer.
func NewRoundRobin(backends []*Backend) *RoundRobin {
	return &RoundRobin{
		backends: backends,
	}
}

// Select picks the next healthy backend in round-robin order.
func (rr *RoundRobin) Select(r *http.Request) *Backend {
	n := len(rr.backends)
	if n == 0 {
		return nil
	}
	// Try all backends starting from current counter
	start := rr.counter.Add(1) - 1
	for i := 0; i < n; i++ {
		idx := (int(start) + i) % n
		b := rr.backends[idx]
		if b.IsHealthy() {
			return b
		}
	}
	return nil
}

// --- Weighted ---

// Weighted selects backends by weight using weighted random selection.
type Weighted struct {
	backends    []*Backend
	totalWeight int
}

// NewWeighted creates a new weighted load balancer.
func NewWeighted(backends []*Backend) *Weighted {
	total := 0
	for _, b := range backends {
		w := b.Weight
		if w <= 0 {
			w = 1
		}
		total += w
	}
	return &Weighted{
		backends:    backends,
		totalWeight: total,
	}
}

// Select picks a healthy backend based on weighted random selection.
func (w *Weighted) Select(r *http.Request) *Backend {
	if len(w.backends) == 0 {
		return nil
	}

	// Calculate total weight of healthy backends
	healthyWeight := 0
	for _, b := range w.backends {
		if b.IsHealthy() {
			wt := b.Weight
			if wt <= 0 {
				wt = 1
			}
			healthyWeight += wt
		}
	}
	if healthyWeight == 0 {
		return nil
	}

	// Pick a random number in [0, healthyWeight)
	rnd := rand.IntN(healthyWeight)
	cumulative := 0
	for _, b := range w.backends {
		if !b.IsHealthy() {
			continue
		}
		wt := b.Weight
		if wt <= 0 {
			wt = 1
		}
		cumulative += wt
		if rnd < cumulative {
			return b
		}
	}

	// Should not reach here, but fallback
	return nil
}

// --- Least Connections ---

// LeastConn selects the backend with the fewest active connections.
type LeastConn struct {
	backends []*Backend
}

// NewLeastConn creates a new least-connections load balancer.
func NewLeastConn(backends []*Backend) *LeastConn {
	return &LeastConn{
		backends: backends,
	}
}

// Select picks the healthy backend with the fewest active connections.
func (lc *LeastConn) Select(r *http.Request) *Backend {
	var best *Backend
	var bestConns int64 = -1

	for _, b := range lc.backends {
		if !b.IsHealthy() {
			continue
		}
		conns := b.ActiveConns.Load()
		if best == nil || conns < bestConns {
			best = b
			bestConns = conns
		}
	}
	return best
}

// --- IP Hash ---

// IPHash selects a backend based on client IP hash for session affinity.
type IPHash struct {
	backends []*Backend
}

// NewIPHash creates a new IP-hash load balancer.
func NewIPHash(backends []*Backend) *IPHash {
	return &IPHash{
		backends: backends,
	}
}

// Select picks a backend deterministically based on the client IP.
func (ih *IPHash) Select(r *http.Request) *Backend {
	if len(ih.backends) == 0 {
		return nil
	}

	// Count healthy backends
	healthy := make([]*Backend, 0, len(ih.backends))
	for _, b := range ih.backends {
		if b.IsHealthy() {
			healthy = append(healthy, b)
		}
	}
	if len(healthy) == 0 {
		return nil
	}

	ip := ClientIP(r)
	h := fnv.New32a()
	h.Write([]byte(ip))
	idx := int(h.Sum32()) % len(healthy)
	return healthy[idx]
}

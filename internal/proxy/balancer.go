package proxy

import (
	"hash/fnv"
	"math"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
)

// Strategy names for load balancing.
const (
	StrategyRoundRobin = "round_robin"
	StrategyWeighted   = "weighted"
	StrategyLeastConn  = "least_conn"
	StrategyIPHash     = "ip_hash"
)

// Balancer distributes requests across multiple targets using a configurable strategy.
type Balancer struct {
	targets  []*Target
	strategy string
	counter  atomic.Uint64
	mu       sync.RWMutex // protects targets slice for health updates
}

// NewBalancer creates a balancer with the given targets and strategy.
func NewBalancer(targets []*Target, strategy string) *Balancer {
	if strategy == "" {
		strategy = StrategyRoundRobin
	}
	return &Balancer{
		targets:  targets,
		strategy: strategy,
	}
}

// Next selects the next healthy target based on the load balancing strategy.
// Returns nil if no healthy targets are available.
func (b *Balancer) Next(r *http.Request) *Target {
	healthy := b.healthyTargets()
	if len(healthy) == 0 {
		return nil
	}

	switch b.strategy {
	case StrategyWeighted:
		return b.weightedRoundRobin(healthy)
	case StrategyLeastConn:
		return b.leastConnections(healthy)
	case StrategyIPHash:
		return b.ipHash(healthy, r)
	default: // round_robin
		return b.roundRobin(healthy)
	}
}

// Targets returns the list of all targets.
func (b *Balancer) Targets() []*Target {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]*Target, len(b.targets))
	copy(out, b.targets)
	return out
}

// Len returns the number of targets.
func (b *Balancer) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.targets)
}

// Strategy returns the strategy name.
func (b *Balancer) Strategy() string {
	return b.strategy
}

// --- Strategies ---

func (b *Balancer) healthyTargets() []*Target {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var result []*Target
	for _, t := range b.targets {
		if t.IsHealthy() {
			result = append(result, t)
		}
	}
	return result
}

func (b *Balancer) roundRobin(healthy []*Target) *Target {
	idx := b.counter.Add(1) - 1
	return healthy[idx%uint64(len(healthy))]
}

// weightedRoundRobin uses smooth weighted round-robin (Nginx-style).
// For simplicity, expand targets by weight and round-robin over expanded list.
func (b *Balancer) weightedRoundRobin(healthy []*Target) *Target {
	var totalWeight uint64
	for _, t := range healthy {
		if t.Weight > 0 {
			totalWeight += uint64(t.Weight)
		}
	}
	if totalWeight == 0 {
		return healthy[0]
	}

	idx := (b.counter.Add(1) - 1) % totalWeight
	var cumulative uint64
	for _, t := range healthy {
		if t.Weight <= 0 {
			continue
		}
		cumulative += uint64(t.Weight)
		if idx < cumulative {
			return t
		}
	}
	return healthy[len(healthy)-1]
}

func (b *Balancer) leastConnections(healthy []*Target) *Target {
	var best *Target
	var bestConns int64 = math.MaxInt64
	for _, t := range healthy {
		conns := t.ActiveConns()
		if conns < bestConns {
			bestConns = conns
			best = t
		}
	}
	return best
}

func (b *Balancer) ipHash(healthy []*Target, r *http.Request) *Target {
	ip := extractClientIPForHash(r)
	h := fnv.New32a()
	h.Write([]byte(ip)) // #nosec G104 -- fnv.Write never returns a non-nil error
	// #nosec G115 -- modulo by len(healthy) guarantees the result fits a slice index.
	idx := int(uint64(h.Sum32()) % uint64(len(healthy)))
	return healthy[idx]
}

// extractClientIPForHash gets the client IP for consistent hashing.
// Uses RemoteAddr only — proxy headers are not trusted here since they can be
// spoofed. The engine's extractClientIP (with trusted proxy support) should be
// used for security decisions. For load balancing hash stability, RemoteAddr is
// sufficient when behind a known proxy.
func extractClientIPForHash(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

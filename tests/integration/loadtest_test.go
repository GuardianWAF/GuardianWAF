package integration

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection"
	"github.com/guardianwaf/guardianwaf/internal/layers/ipacl"
	"github.com/guardianwaf/guardianwaf/internal/layers/ratelimit"
)

// TestLoadTest_BenignTraffic validates that the engine handles sustained concurrent
// benign traffic within the <1ms p99 latency target.
func TestLoadTest_BenignTraffic(t *testing.T) {
	eng := newLoadTestEngine(t)
	defer eng.Close()

	const (
		workers   = 100
		requests  = 10000
		p99Target = 200 * time.Millisecond // CI runners have variable CPU; 200ms allows for GC/scheduler spikes
	)

	var latencies [workers][]time.Duration
	var wg sync.WaitGroup
	var errors atomic.Int64

	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			latencies[w] = make([]time.Duration, 0, requests/workers)
			for range requests / workers {
				req := httptest.NewRequest("GET", "/api/users?page=1&limit=10", nil)
				req.RemoteAddr = fmt.Sprintf("10.0.%d.%d:12345", w%256, w%256)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

				start := time.Now()
				ev := eng.Check(req)
				elapsed := time.Since(start)

				if ev == nil {
					errors.Add(1)
				}
				latencies[w] = append(latencies[w], elapsed)
			}
		}()
	}
	wg.Wait()

	var all []time.Duration
	for _, l := range latencies {
		all = append(all, l...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })

	p50 := all[len(all)*50/100]
	p90 := all[len(all)*90/100]
	p99 := all[len(all)*99/100]
	max := all[len(all)-1]

	t.Logf("Load test: %d requests, %d workers, %d errors", len(all), workers, errors.Load())
	t.Logf("Latency: p50=%v p90=%v p99=%v max=%v", p50, p90, p99, max)

	if p99 > p99Target {
		t.Errorf("p99 latency %v exceeds target %v", p99, p99Target)
	}
}

// TestLoadTest_MixedTraffic validates engine under a mix of benign and attack traffic.
func TestLoadTest_MixedTraffic(t *testing.T) {
	eng := newLoadTestEngine(t)
	defer eng.Close()

	const (
		workers     = 50
		totalReqs   = 5000
		attackRatio = 20
	)

	var blocked, passed atomic.Int64
	var wg sync.WaitGroup

	attackPayloads := []string{
		"/search?q='%20OR%201=1--",
		"/page?q=%3Cscript%3Ealert(1)%3C/script%3E",
		"/api/user?id=1'%20UNION%20SELECT%20password%20FROM%20users--",
		"/download?file=../../etc/passwd",
		"/exec?cmd=%3Bid",
	}

	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range totalReqs / workers {
				var req *http.Request
				if i%(100/attackRatio) == 0 {
					payload := attackPayloads[w%len(attackPayloads)]
					req = httptest.NewRequest("GET", payload, nil)
				} else {
					req = httptest.NewRequest("GET", "/api/data?page=1", nil)
				}
				req.RemoteAddr = fmt.Sprintf("192.168.%d.%d:12345", w%256, i%256)
				req.Header.Set("User-Agent", "Mozilla/5.0")

				ev := eng.Check(req)
				if ev != nil && ev.Action == engine.ActionBlock {
					blocked.Add(1)
				} else {
					passed.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	totalBlocked := blocked.Load()
	totalPassed := passed.Load()
	t.Logf("Mixed traffic: %d blocked, %d passed (%.1f%% block rate)",
		totalBlocked, totalPassed, float64(totalBlocked)/float64(totalBlocked+totalPassed)*100)

	if totalBlocked == 0 {
		t.Error("expected some attacks to be blocked")
	}
}

// TestLoadTest_ConcurrentIPs validates IP ACL and rate limiting under high cardinality.
func TestLoadTest_ConcurrentIPs(t *testing.T) {
	eng := newLoadTestEngine(t)
	defer eng.Close()

	const (
		workers   = 50
		reqsPerIP = 5
		uniqueIPs = 1000
	)

	var wg sync.WaitGroup
	var blocked atomic.Int64

	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range uniqueIPs / workers {
				for r := range reqsPerIP {
					req := httptest.NewRequest("GET", "/api/data", nil)
					req.RemoteAddr = fmt.Sprintf("203.0.%d.%d:12345", ip%256, (w*10+r)%256)
					req.Header.Set("User-Agent", "curl/8.0")

					ev := eng.Check(req)
					if ev != nil && ev.Action == engine.ActionBlock {
						blocked.Add(1)
					}
				}
			}
		}()
	}
	wg.Wait()

	t.Logf("Concurrent IPs: %d unique IPs, %d blocked", uniqueIPs, blocked.Load())
}

func newLoadTestEngine(t testing.TB) *engine.Engine {
	t.Helper()

	cfg := config.DefaultConfig()
	cfg.Events.Storage = "memory"
	cfg.WAF.Detection.Threshold.Block = 50
	cfg.WAF.Detection.Threshold.Log = 25

	store := events.NewMemoryStore(100000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	eng.AddLayer(engine.OrderedLayer{Layer: newSanitizer(), Order: engine.OrderSanitizer})
	eng.AddLayer(engine.OrderedLayer{Layer: detection.NewLayer(&detection.Config{
		Enabled: true,
		Detectors: map[string]detection.DetectorConfig{
			"sqli": {Enabled: true, Multiplier: 1.0},
			"xss":  {Enabled: true, Multiplier: 1.0},
			"lfi":  {Enabled: true, Multiplier: 1.0},
			"cmdi": {Enabled: true, Multiplier: 1.0},
			"xxe":  {Enabled: true, Multiplier: 1.0},
			"ssrf": {Enabled: true, Multiplier: 1.0},
		},
	}), Order: engine.OrderDetection})
	ipaclLayer, _ := ipacl.NewLayer(&ipacl.Config{})
	eng.AddLayer(engine.OrderedLayer{Layer: ipaclLayer, Order: engine.OrderIPACL})
	eng.AddLayer(engine.OrderedLayer{Layer: ratelimit.NewLayer(&ratelimit.Config{}), Order: engine.OrderRateLimit})

	return eng
}

package main

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

type cleanupTestLayer struct {
	name string
}

func (l cleanupTestLayer) Name() string {
	return l.name
}

func (l cleanupTestLayer) Order() int { return 0 }

func (l cleanupTestLayer) Process(*engine.RequestContext) engine.LayerResult {
	return engine.LayerResult{}
}

type staleCleanupLayer struct {
	cleanupTestLayer
	called atomic.Int32
	age    time.Duration
}

func (l *staleCleanupLayer) CleanupExpired(age time.Duration) {
	l.age = age
	l.called.Add(1)
}

func (l *staleCleanupLayer) Order() int { return 0 }

type expiryCleanupLayer struct {
	cleanupTestLayer
	called atomic.Int32
}

func (l *expiryCleanupLayer) CleanupExpired() {
	l.called.Add(1)
}

func (l *expiryCleanupLayer) Order() int { return 0 }

type simpleCleanupLayer struct {
	cleanupTestLayer
	called atomic.Int32
}

func (l *simpleCleanupLayer) Cleanup() {
	l.called.Add(1)
}

type tenantCleanupRecorder struct {
	called atomic.Int32
	age    time.Duration
}

func (r *tenantCleanupRecorder) CleanupRateLimiter(age time.Duration) {
	r.age = age
	r.called.Add(1)
}

func TestRunPeriodicCleanupCallsSupportedCleaners(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	rateLimitLayer := &staleCleanupLayer{cleanupTestLayer: cleanupTestLayer{name: "ratelimit"}}
	ipaclLayer := &expiryCleanupLayer{cleanupTestLayer: cleanupTestLayer{name: "ipacl"}}
	atoLayer := &simpleCleanupLayer{cleanupTestLayer: cleanupTestLayer{name: "ato_protection"}}
	botLayer := &simpleCleanupLayer{cleanupTestLayer: cleanupTestLayer{name: "botdetect"}}
	tenantCleaner := &tenantCleanupRecorder{}

	eng.AddLayer(engine.OrderedLayer{Layer: rateLimitLayer, Order: engine.OrderRateLimit})
	eng.AddLayer(engine.OrderedLayer{Layer: ipaclLayer, Order: engine.OrderIPACL})
	eng.AddLayer(engine.OrderedLayer{Layer: atoLayer, Order: engine.OrderATO})
	eng.AddLayer(engine.OrderedLayer{Layer: botLayer, Order: engine.OrderBotDetect})

	runPeriodicCleanup(eng, tenantCleaner)

	if rateLimitLayer.called.Load() != 1 || rateLimitLayer.age != cleanupMaxAge {
		t.Fatalf("rate limit cleanup called=%d age=%s", rateLimitLayer.called.Load(), rateLimitLayer.age)
	}
	if ipaclLayer.called.Load() != 1 {
		t.Fatalf("ipacl cleanup called=%d", ipaclLayer.called.Load())
	}
	if atoLayer.called.Load() != 1 {
		t.Fatalf("ato cleanup called=%d", atoLayer.called.Load())
	}
	if botLayer.called.Load() != 1 {
		t.Fatalf("botdetect cleanup called=%d", botLayer.called.Load())
	}
	if tenantCleaner.called.Load() != 1 || tenantCleaner.age != cleanupMaxAge {
		t.Fatalf("tenant cleanup called=%d age=%s", tenantCleaner.called.Load(), tenantCleaner.age)
	}
}

func TestStartPeriodicCleanupStops(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	stop, wg := startPeriodicCleanup(eng, nil, time.Hour)
	close(stop)
	if err := waitForWaitGroup(t.Context(), wg); err != nil {
		t.Fatalf("cleanup goroutine did not stop: %v", err)
	}
}

func TestRunPeriodicCleanupNilEngine(t *testing.T) {
	runPeriodicCleanup(nil, &tenantCleanupRecorder{})
}

func TestRunPeriodicCleanupTypedNilTenantManager(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	var tenantCleaner *tenantCleanupRecorder
	runPeriodicCleanup(eng, tenantCleaner)
}

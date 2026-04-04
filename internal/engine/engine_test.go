package engine

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// --- Mock EventStorer for engine tests ---

// mockEventStore is a minimal in-memory event store for testing.
type mockEventStore struct {
	mu     sync.Mutex
	events []Event
	closed bool
}

func newMockEventStore() *mockEventStore {
	return &mockEventStore{}
}

func (s *mockEventStore) Store(event Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("store closed")
	}
	s.events = append(s.events, event)
	return nil
}

func (s *mockEventStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *mockEventStore) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *mockEventStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

func (s *mockEventStore) get(i int) Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.events[i]
}

// --- Mock EventPublisher for engine tests ---

// mockEventBus is a minimal event bus for testing.
type mockEventBus struct {
	mu          sync.Mutex
	subscribers []chan<- Event
	closed      bool
}

func newMockEventBus() *mockEventBus {
	return &mockEventBus{}
}

func (b *mockEventBus) Subscribe(ch chan<- Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.subscribers = append(b.subscribers, ch)
}

func (b *mockEventBus) Publish(event Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subscribers {
		select {
		case ch <- event:
		default:
		}
	}
}

func (b *mockEventBus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	for _, ch := range b.subscribers {
		close(ch)
	}
	b.subscribers = nil
}

// --- Helpers ---

// testEngine creates a test engine with default config and mock store/bus.
func testEngine(t *testing.T) (*Engine, *mockEventStore, *mockEventBus) {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Events.Storage = "memory"
	cfg.Events.MaxEvents = 1000
	store := newMockEventStore()
	bus := newMockEventBus()
	e, err := NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e, store, bus
}

// testRequest creates a test HTTP request.
func testRequest(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.RemoteAddr = "1.2.3.4:12345"
	return r
}

// --- Tests ---

func TestNewEngine(t *testing.T) {
	e, store, _ := testEngine(t)
	defer e.Close()

	if e == nil {
		t.Fatal("expected non-nil engine")
	}
	if e.Config() == nil {
		t.Fatal("expected non-nil config")
	}
	if e.EventStore() == nil {
		t.Fatal("expected non-nil event store")
	}
	if e.EventBus() == nil {
		t.Fatal("expected non-nil event bus")
	}

	// Verify event store works
	err := store.Store(Event{ID: "test-1"})
	if err != nil {
		t.Fatalf("event store Store failed: %v", err)
	}
	if store.len() != 1 {
		t.Errorf("expected 1 event in store, got %d", store.len())
	}

	// Verify pipeline is initialized
	pipeline := e.currentPipeline()
	if pipeline == nil {
		t.Fatal("expected non-nil pipeline")
	}
	layers := pipeline.Layers()
	if len(layers) != 0 {
		t.Errorf("expected 0 layers in fresh engine, got %d", len(layers))
	}

	// Verify thresholds from default config
	if e.blockThreshold != 50 {
		t.Errorf("expected blockThreshold 50, got %d", e.blockThreshold)
	}
	if e.logThreshold != 25 {
		t.Errorf("expected logThreshold 25, got %d", e.logThreshold)
	}
}

func TestNewEngine_NilStore(t *testing.T) {
	cfg := config.DefaultConfig()
	bus := newMockEventBus()
	_, err := NewEngine(cfg, nil, bus)
	if err == nil {
		t.Fatal("expected error for nil eventStore")
	}
}

func TestNewEngine_NilBus(t *testing.T) {
	cfg := config.DefaultConfig()
	store := newMockEventStore()
	_, err := NewEngine(cfg, store, nil)
	if err == nil {
		t.Fatal("expected error for nil eventBus")
	}
}

func TestNewEngine_WithExclusions(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Detection.Exclusions = []config.ExclusionConfig{
		{
			Path:      "/api/webhook",
			Detectors: []string{"sqli", "xss"},
			Reason:    "webhook payloads",
		},
	}

	store := newMockEventStore()
	bus := newMockEventBus()
	e, err := NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine with exclusions: %v", err)
	}
	defer e.Close()

	// Verify the exclusion is applied by adding a mock detector and checking behavior
	sqli := &mockDetector{name: "sqli-layer", detName: "sqli", score: 60}
	e.AddLayer(OrderedLayer{Layer: sqli, Order: OrderDetection})

	// Request to excluded path should skip sqli
	r := testRequest("GET", "/api/webhook/stripe")
	event := e.Check(r)
	if event.Score != 0 {
		t.Errorf("expected score 0 for excluded path, got %d", event.Score)
	}

	// Request to non-excluded path should run sqli
	r2 := testRequest("GET", "/other")
	event2 := e.Check(r2)
	if event2.Score == 0 {
		t.Error("expected non-zero score for non-excluded path")
	}
}

func TestEngine_Check_PassThrough(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Engine with no layers — everything should pass
	r := testRequest("GET", "/hello")
	event := e.Check(r)

	if event.Action != ActionPass {
		t.Errorf("expected ActionPass, got %v", event.Action)
	}
	if event.Score != 0 {
		t.Errorf("expected score 0, got %d", event.Score)
	}
	if len(event.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(event.Findings))
	}
	if event.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", event.StatusCode)
	}
	if event.RequestID == "" {
		t.Error("expected non-empty RequestID")
	}
}

func TestEngine_Check_WithScoreLayer_BelowThresholds(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Add a score layer with score below log threshold (25)
	e.AddLayer(OrderedLayer{
		Layer: &scoreLayer{name: "low-score", score: 10, category: "test"},
		Order: OrderDetection,
	})

	r := testRequest("GET", "/test?q=payload")
	event := e.Check(r)

	// Score 10 is below log threshold (25), so should pass
	if event.Action != ActionPass {
		t.Errorf("expected ActionPass (score below log threshold), got %v", event.Action)
	}
	if event.Score != 10 {
		t.Errorf("expected score 10, got %d", event.Score)
	}
	if event.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", event.StatusCode)
	}
}

func TestEngine_Check_WithScoreLayer_LogThreshold(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Add a score layer with score at log threshold (25) but below block (50)
	e.AddLayer(OrderedLayer{
		Layer: &scoreLayer{name: "mid-score", score: 30, category: "test"},
		Order: OrderDetection,
	})

	r := testRequest("GET", "/test?q=payload")
	event := e.Check(r)

	// Score 30 >= log threshold (25) but < block threshold (50)
	if event.Action != ActionLog {
		t.Errorf("expected ActionLog, got %v", event.Action)
	}
	if event.Score != 30 {
		t.Errorf("expected score 30, got %d", event.Score)
	}
	if event.StatusCode != 200 {
		t.Errorf("expected status 200 (log, not block), got %d", event.StatusCode)
	}
}

func TestEngine_Check_BlockOnThreshold(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Add score layers that together exceed the block threshold (50)
	e.AddLayer(OrderedLayer{
		Layer: &scoreLayer{name: "sqli", score: 30, category: "sqli"},
		Order: OrderDetection,
	})
	e.AddLayer(OrderedLayer{
		Layer: &scoreLayer{name: "xss", score: 25, category: "xss"},
		Order: OrderDetection + 10,
	})

	r := testRequest("GET", "/test?q=payload")
	event := e.Check(r)

	// Total score 55 >= block threshold (50)
	if event.Action != ActionBlock {
		t.Errorf("expected ActionBlock, got %v", event.Action)
	}
	if event.Score != 55 {
		t.Errorf("expected score 55, got %d", event.Score)
	}
	if event.StatusCode != 403 {
		t.Errorf("expected status 403, got %d", event.StatusCode)
	}
	if len(event.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(event.Findings))
	}
}

func TestEngine_Check_BlockLayer(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Add a block layer (e.g., IP ACL block)
	e.AddLayer(OrderedLayer{
		Layer: &blockLayer{name: "ip-acl"},
		Order: OrderIPACL,
	})

	r := testRequest("GET", "/any-path")
	event := e.Check(r)

	if event.Action != ActionBlock {
		t.Errorf("expected ActionBlock from block layer, got %v", event.Action)
	}
	if event.StatusCode != 403 {
		t.Errorf("expected status 403, got %d", event.StatusCode)
	}
}

func TestEngine_Check_StatsUpdate(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Initially all stats should be zero
	stats := e.Stats()
	if stats.TotalRequests != 0 {
		t.Errorf("expected 0 total requests, got %d", stats.TotalRequests)
	}

	// Send a passing request
	r1 := testRequest("GET", "/pass")
	e.Check(r1)

	// Add a block layer and send a blocking request
	e.AddLayer(OrderedLayer{
		Layer: &blockLayer{name: "blocker"},
		Order: OrderIPACL,
	})
	r2 := testRequest("GET", "/blocked")
	e.Check(r2)

	stats = e.Stats()
	if stats.TotalRequests != 2 {
		t.Errorf("expected 2 total requests, got %d", stats.TotalRequests)
	}
	if stats.PassedRequests != 1 {
		t.Errorf("expected 1 passed request, got %d", stats.PassedRequests)
	}
	if stats.BlockedRequests != 1 {
		t.Errorf("expected 1 blocked request, got %d", stats.BlockedRequests)
	}
}

func TestEngine_Check_StatsUpdate_WithLogAction(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Add a score layer that triggers log action
	e.AddLayer(OrderedLayer{
		Layer: &scoreLayer{name: "detector", score: 30, category: "test"},
		Order: OrderDetection,
	})

	r := testRequest("GET", "/suspicious")
	e.Check(r)

	stats := e.Stats()
	if stats.TotalRequests != 1 {
		t.Errorf("expected 1 total request, got %d", stats.TotalRequests)
	}
	if stats.LoggedRequests != 1 {
		t.Errorf("expected 1 logged request, got %d", stats.LoggedRequests)
	}
	if stats.AvgLatencyUs < 0 {
		t.Error("average latency should not be negative")
	}
}

func TestEngine_Check_EventStored(t *testing.T) {
	e, store, _ := testEngine(t)
	defer e.Close()

	r := testRequest("GET", "/store-test")
	event := e.Check(r)

	if store.len() != 1 {
		t.Fatalf("expected 1 event in store, got %d", store.len())
	}

	stored := store.get(0)
	if stored.RequestID != event.RequestID {
		t.Errorf("stored event RequestID %q does not match returned %q", stored.RequestID, event.RequestID)
	}
	if stored.Path != "/store-test" {
		t.Errorf("expected path /store-test, got %s", stored.Path)
	}
	if stored.Method != "GET" {
		t.Errorf("expected method GET, got %s", stored.Method)
	}
	if stored.ClientIP != "1.2.3.4" {
		t.Errorf("expected client IP 1.2.3.4, got %s", stored.ClientIP)
	}
}

func TestEngine_Check_EventPublished(t *testing.T) {
	e, _, bus := testEngine(t)

	ch := make(chan Event, 10)
	bus.Subscribe(ch)

	r := testRequest("GET", "/publish-test")
	event := e.Check(r)

	// Should receive the event on the channel
	select {
	case received := <-ch:
		if received.RequestID != event.RequestID {
			t.Errorf("published event RequestID %q does not match returned %q", received.RequestID, event.RequestID)
		}
		if received.Path != "/publish-test" {
			t.Errorf("expected path /publish-test, got %s", received.Path)
		}
	default:
		t.Fatal("expected event to be published on the bus")
	}

	e.Close()
}

func TestEngine_Middleware_Pass(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Set up a next handler that records it was called
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	handler := e.Middleware(next)
	rec := httptest.NewRecorder()
	r := testRequest("GET", "/pass-through")

	handler.ServeHTTP(rec, r)

	if !nextCalled {
		t.Error("expected next handler to be called for passing request")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if rec.Body.String() != "OK" {
		t.Errorf("expected body 'OK', got %q", rec.Body.String())
	}
}

func TestEngine_Middleware_Block(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Add a block layer
	e.AddLayer(OrderedLayer{
		Layer: &blockLayer{name: "blocker"},
		Order: OrderIPACL,
	})

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	handler := e.Middleware(next)
	rec := httptest.NewRecorder()
	r := testRequest("GET", "/blocked")

	handler.ServeHTTP(rec, r)

	if nextCalled {
		t.Error("next handler should NOT be called for blocked request")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Request Blocked") {
		t.Errorf("block response should contain 'Request Blocked', got: %.100s", body)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "text/html; charset=utf-8" {
		t.Errorf("expected Content-Type 'text/html; charset=utf-8', got %q", ct)
	}
}

func TestEngine_Middleware_RequestID(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Test request ID on passing request
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := e.Middleware(next)

	rec := httptest.NewRecorder()
	r := testRequest("GET", "/id-test")
	handler.ServeHTTP(rec, r)

	reqID := rec.Header().Get("X-GuardianWAF-RequestID")
	if reqID == "" {
		t.Error("expected X-GuardianWAF-RequestID header on passing request")
	}

	// Test request ID on blocked request
	e.AddLayer(OrderedLayer{
		Layer: &blockLayer{name: "blocker"},
		Order: OrderIPACL,
	})

	rec2 := httptest.NewRecorder()
	r2 := testRequest("GET", "/id-test-blocked")
	handler.ServeHTTP(rec2, r2)

	reqID2 := rec2.Header().Get("X-GuardianWAF-RequestID")
	if reqID2 == "" {
		t.Error("expected X-GuardianWAF-RequestID header on blocked request")
	}

	// Request IDs should be different
	if reqID == reqID2 {
		t.Error("request IDs should be unique across requests")
	}
}

func TestEngine_Reload(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Initial thresholds from default config
	if e.blockThreshold != 50 {
		t.Fatalf("expected initial blockThreshold 50, got %d", e.blockThreshold)
	}
	if e.logThreshold != 25 {
		t.Fatalf("expected initial logThreshold 25, got %d", e.logThreshold)
	}

	// Add a score layer with score 35
	e.AddLayer(OrderedLayer{
		Layer: &scoreLayer{name: "detector", score: 35, category: "test"},
		Order: OrderDetection,
	})

	// With original thresholds: score 35 >= log (25) but < block (50) = ActionLog
	r1 := testRequest("GET", "/test")
	event1 := e.Check(r1)
	if event1.Action != ActionLog {
		t.Errorf("before reload: expected ActionLog, got %v", event1.Action)
	}

	// Reload with lower block threshold
	newCfg := config.DefaultConfig()
	newCfg.WAF.Detection.Threshold.Block = 30
	newCfg.WAF.Detection.Threshold.Log = 10
	err := e.Reload(newCfg)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// Verify thresholds updated
	if e.blockThreshold != 30 {
		t.Errorf("expected reloaded blockThreshold 30, got %d", e.blockThreshold)
	}
	if e.logThreshold != 10 {
		t.Errorf("expected reloaded logThreshold 10, got %d", e.logThreshold)
	}

	// With new thresholds: score 35 >= block (30) = ActionBlock
	r2 := testRequest("GET", "/test")
	event2 := e.Check(r2)
	if event2.Action != ActionBlock {
		t.Errorf("after reload: expected ActionBlock, got %v", event2.Action)
	}
}

func TestEngine_Reload_MaxBodySize(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	newCfg := config.DefaultConfig()
	newCfg.WAF.Sanitizer.MaxBodySize = 512
	err := e.Reload(newCfg)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if e.maxBodySize != 512 {
		t.Errorf("expected maxBodySize 512, got %d", e.maxBodySize)
	}
}

func TestEngine_Concurrent(t *testing.T) {
	e, store, _ := testEngine(t)
	defer e.Close()

	// Add a score layer that produces findings
	e.AddLayer(OrderedLayer{
		Layer: &scoreLayer{name: "detector", score: 15, category: "test"},
		Order: OrderDetection,
	})

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	errs := make(chan string, goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			r := testRequest("GET", "/concurrent")
			event := e.Check(r)

			if event == nil {
				errs <- "nil event returned"
				return
			}
			if event.RequestID == "" {
				errs <- "empty request ID"
				return
			}
			if event.Score != 15 {
				errs <- "unexpected score"
				return
			}
			if len(event.Findings) != 1 {
				errs <- "unexpected findings count"
				return
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	// Verify stats are consistent
	stats := e.Stats()
	if stats.TotalRequests != int64(goroutines) {
		t.Errorf("expected %d total requests, got %d", goroutines, stats.TotalRequests)
	}

	// All requests should be passed (score 15 < log threshold 25)
	if stats.PassedRequests != int64(goroutines) {
		t.Errorf("expected %d passed requests, got %d", goroutines, stats.PassedRequests)
	}

	// Verify all events were stored
	if store.len() != goroutines {
		t.Errorf("expected %d events in store, got %d", goroutines, store.len())
	}
}

func TestEngine_Concurrent_MixedActions(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Add a score layer with score at log threshold
	e.AddLayer(OrderedLayer{
		Layer: &scoreLayer{name: "detector", score: 30, category: "test"},
		Order: OrderDetection,
	})

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			r := testRequest("GET", "/concurrent-log")
			e.Check(r)
		}()
	}
	wg.Wait()

	stats := e.Stats()
	if stats.TotalRequests != int64(goroutines) {
		t.Errorf("expected %d total requests, got %d", goroutines, stats.TotalRequests)
	}
	// Score 30 >= log threshold 25, all should be logged
	if stats.LoggedRequests != int64(goroutines) {
		t.Errorf("expected %d logged requests, got %d", goroutines, stats.LoggedRequests)
	}
	if stats.BlockedRequests != 0 {
		t.Errorf("expected 0 blocked requests, got %d", stats.BlockedRequests)
	}
	if stats.PassedRequests != 0 {
		t.Errorf("expected 0 passed requests, got %d", stats.PassedRequests)
	}
}

func TestEngine_Close(t *testing.T) {
	e, store, bus := testEngine(t)

	err := e.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Verify event store is closed
	if !store.isClosed() {
		t.Error("expected event store to be closed")
	}

	// Verify event bus is closed
	if !bus.closed {
		t.Error("expected event bus to be closed")
	}
}

func TestEngine_Stats_AvgLatency(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Initial average latency should be 0
	stats := e.Stats()
	if stats.AvgLatencyUs != 0 {
		t.Errorf("expected initial avg latency 0, got %d", stats.AvgLatencyUs)
	}

	// Process some requests
	for range 5 {
		r := testRequest("GET", "/latency-test")
		e.Check(r)
	}

	stats = e.Stats()
	if stats.TotalRequests != 5 {
		t.Errorf("expected 5 total requests, got %d", stats.TotalRequests)
	}
	// Avg latency should be non-negative (likely very small but non-negative)
	if stats.AvgLatencyUs < 0 {
		t.Errorf("average latency should be non-negative, got %d", stats.AvgLatencyUs)
	}
}

func TestEngine_AddLayer(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Start with empty pipeline
	layers := e.currentPipeline().Layers()
	if len(layers) != 0 {
		t.Fatalf("expected 0 layers initially, got %d", len(layers))
	}

	// Add layers
	e.AddLayer(OrderedLayer{Layer: &passLayer{name: "sanitizer"}, Order: OrderSanitizer})
	e.AddLayer(OrderedLayer{Layer: &passLayer{name: "ipacl"}, Order: OrderIPACL})

	layers = e.currentPipeline().Layers()
	if len(layers) != 2 {
		t.Fatalf("expected 2 layers, got %d", len(layers))
	}
	// Should be sorted by order
	if layers[0].Layer.Name() != "ipacl" {
		t.Errorf("first layer should be 'ipacl' (order 100), got %q", layers[0].Layer.Name())
	}
	if layers[1].Layer.Name() != "sanitizer" {
		t.Errorf("second layer should be 'sanitizer' (order 300), got %q", layers[1].Layer.Name())
	}
}

func TestEngine_Check_BlockLayerOverridesScoreThreshold(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Add a block layer even though score might be 0
	// The pipeline returns ActionBlock which should override score-based logic
	e.AddLayer(OrderedLayer{
		Layer: &blockLayer{name: "rate-limiter"},
		Order: OrderRateLimit,
	})

	r := testRequest("GET", "/rate-limited")
	event := e.Check(r)

	if event.Action != ActionBlock {
		t.Errorf("expected ActionBlock from block layer, got %v", event.Action)
	}
	if event.StatusCode != 403 {
		t.Errorf("expected status 403, got %d", event.StatusCode)
	}
}

func TestEngine_Check_EventFields(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	r := testRequest("POST", "/api/data?key=value")
	r.Header.Set("User-Agent", "TestAgent/1.0")

	event := e.Check(r)

	if event.Method != "POST" {
		t.Errorf("expected method POST, got %s", event.Method)
	}
	if event.Path != "/api/data" {
		t.Errorf("expected path /api/data, got %s", event.Path)
	}
	if event.ClientIP != "1.2.3.4" {
		t.Errorf("expected client IP 1.2.3.4, got %s", event.ClientIP)
	}
	if event.RequestID == "" {
		t.Error("expected non-empty request ID")
	}
	if event.Duration < 0 {
		t.Error("event duration should be non-negative")
	}
}

func TestEngine_Middleware_PassSetsHeaders(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	var receivedReqIDHeader string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The request ID should be set in response headers before ServeHTTP
		receivedReqIDHeader = w.Header().Get("X-GuardianWAF-RequestID")
		w.WriteHeader(http.StatusOK)
	})

	handler := e.Middleware(next)
	rec := httptest.NewRecorder()
	r := testRequest("GET", "/headers-test")
	handler.ServeHTTP(rec, r)

	// The header should be set on the response
	finalReqID := rec.Header().Get("X-GuardianWAF-RequestID")
	if finalReqID == "" {
		t.Error("expected X-GuardianWAF-RequestID header in response")
	}
	// The next handler should see the header set
	if receivedReqIDHeader == "" {
		t.Error("expected X-GuardianWAF-RequestID to be set before next handler")
	}
}

func TestEngine_Config(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	cfg := e.Config()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Mode != "enforce" {
		t.Errorf("expected mode 'enforce', got %q", cfg.Mode)
	}
}

func TestEngine_Check_ScoreExactlyAtBlockThreshold(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Default block threshold is 50
	// Add a layer that produces exactly score 50
	e.AddLayer(OrderedLayer{
		Layer: &scoreLayer{name: "exact-block", score: 50, category: "test"},
		Order: OrderDetection,
	})

	r := testRequest("GET", "/exact-threshold")
	event := e.Check(r)

	// Score 50 >= blockThreshold 50 should result in block
	if event.Action != ActionBlock {
		t.Errorf("expected ActionBlock at exact threshold, got %v", event.Action)
	}
}

func TestEngine_Check_ScoreExactlyAtLogThreshold(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Default log threshold is 25
	e.AddLayer(OrderedLayer{
		Layer: &scoreLayer{name: "exact-log", score: 25, category: "test"},
		Order: OrderDetection,
	})

	r := testRequest("GET", "/exact-log-threshold")
	event := e.Check(r)

	// Score 25 >= logThreshold 25 should result in log
	if event.Action != ActionLog {
		t.Errorf("expected ActionLog at exact log threshold, got %v", event.Action)
	}
}

// --- applyResponseHook tests ---

func TestApplyResponseHook_WithHook(t *testing.T) {
	w := httptest.NewRecorder()
	metadata := map[string]any{
		"response_hook": func(w http.ResponseWriter) {
			w.Header().Set("X-Test-Header", "applied")
		},
	}
	applyResponseHook(w, metadata)
	if w.Header().Get("X-Test-Header") != "applied" {
		t.Error("expected response hook to set X-Test-Header")
	}
}

func TestApplyResponseHook_NoHook(t *testing.T) {
	w := httptest.NewRecorder()
	metadata := map[string]any{}
	applyResponseHook(w, metadata)
	// Should not panic, no headers added
	if len(w.Header()) != 0 {
		t.Error("expected no headers when no hook is set")
	}
}

func TestApplyResponseHook_WrongType(t *testing.T) {
	w := httptest.NewRecorder()
	metadata := map[string]any{
		"response_hook": "not-a-function",
	}
	applyResponseHook(w, metadata)
	// Should not panic
	if len(w.Header()) != 0 {
		t.Error("expected no headers for wrong type")
	}
}

// --- Middleware with response hook (security headers) ---

func TestMiddleware_AppliesSecurityHeaders(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Response.SecurityHeaders.Enabled = true

	e, cleanup := setupEngineWithLayers(t, cfg)
	defer cleanup()

	handler := e.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Verify security headers were applied
	if rr.Header().Get("X-GuardianWAF-RequestID") == "" {
		t.Error("expected X-GuardianWAF-RequestID header")
	}
}

func TestMiddleware_LogAction(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Detection.Threshold.Block = 100
	cfg.WAF.Detection.Threshold.Log = 10

	e, cleanup := setupEngineWithLayers(t, cfg)
	defer cleanup()

	handler := e.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Medium-suspicion request — should be logged but not blocked
	req := httptest.NewRequest("GET", "/search?q=SELECT+*+FROM", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should not be blocked (threshold is 100)
	if rr.Code == http.StatusForbidden {
		t.Error("expected non-blocked response for log threshold")
	}
}

// setupEngineWithLayers creates a test engine with response layer
func setupEngineWithLayers(t *testing.T, cfg *config.Config) (*Engine, func()) {
	t.Helper()
	store := newMockEventStore()
	bus := newMockEventBus()
	eng, err := NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}

	// Add a response layer that sets security headers
	if cfg.WAF.Response.SecurityHeaders.Enabled {
		eng.AddLayer(OrderedLayer{
			Layer: &mockResponseLayer{
				securityHeaders: true,
			},
			Order: OrderResponse,
		})
	}

	return eng, func() { eng.Close() }
}

// mockResponseLayer simulates the response layer setting a hook
type mockResponseLayer struct {
	securityHeaders bool
}

func (l *mockResponseLayer) Name() string { return "response" }

func (l *mockResponseLayer) Process(ctx *RequestContext) LayerResult {
	ctx.Metadata["response_config"] = "test"
	if l.securityHeaders {
		ctx.Metadata["response_hook"] = func(w http.ResponseWriter) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		}
	}
	return LayerResult{Action: ActionPass}
}

// --- TLS Helper Functions ---

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		version  uint16
		expected string
	}{
		{0x0304, "TLS 1.3"},
		{0x0303, "TLS 1.2"},
		{0x0302, "TLS 1.1"},
		{0x0301, "TLS 1.0"},
		{0xfeff, "DTLS 1.0"},
		{0xfefd, "DTLS 1.2"},
		{0x0000, "Unknown"},
	}

	for _, tt := range tests {
		result := tlsVersionString(tt.version)
		if result != tt.expected {
			t.Errorf("tlsVersionString(0x%04x) = %q, expected %q", tt.version, result, tt.expected)
		}
	}
}

func TestTLSCipherString(t *testing.T) {
	tests := []struct {
		cipher   uint16
		expected string
	}{
		{0x1301, "TLS_AES_128_GCM_SHA256"},
		{0x1302, "TLS_AES_256_GCM_SHA384"},
		{0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
		{0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
		{0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		{0x0000, "Unknown"},
	}

	for _, tt := range tests {
		result := tlsCipherString(tt.cipher)
		if result != tt.expected {
			t.Errorf("tlsCipherString(0x%04x) = %q, expected %q", tt.cipher, result, tt.expected)
		}
	}
}

func TestComputePartialJA3(t *testing.T) {
	result := computePartialJA3(0x0303, 0xc02f)
	// Should be a hex string of combined version and cipher
	if len(result) != 8 {
		t.Errorf("expected 8 char hex string, got %q (len=%d)", result, len(result))
	}
}

func TestComputeJA4FromContext(t *testing.T) {
	tests := []struct {
		name     string
		ctx      *RequestContext
		contains string
	}{
		{
			name: "minimal context",
			ctx: &RequestContext{
				TLSVersion: 0x0304,
			},
			contains: "t13",
		},
		{
			name: "with JA4 fields",
			ctx: &RequestContext{
				TLSVersion:  0x0303,
				JA4Protocol: "t",
				JA4SNI:      true,
				JA4Ciphers:  []uint16{0x1301, 0x1302},
				JA4Exts:     []uint16{0x001b},
				JA4ALPN:     "h2",
				JA4Ver:      0x0304,
			},
			contains: "t13d02",
		},
		{
			name: "QUIC protocol",
			ctx: &RequestContext{
				TLSVersion:  0x0304,
				JA4Protocol: "q",
				JA4Ciphers:  []uint16{0x1301},
				JA4ALPN:     "h3",
			},
			contains: "q13",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := computeJA4FromContext(tt.ctx)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("computeJA4FromContext() = %q, expected to contain %q", result, tt.contains)
			}
		})
	}
}

func TestNewEvent_WithTLS(t *testing.T) {
	// Create a request with TLS info
	req := httptest.NewRequest("GET", "https://example.com/test", nil)
	req.TLS = &tls.ConnectionState{
		Version:            0x0303,
		CipherSuite:        0xc02f,
		ServerName:         "example.com",
		NegotiatedProtocol: "h2",
	}

	ctx := AcquireContext(req, 1, 1024*1024)
	ctx.JA4Ciphers = []uint16{0x1301, 0x1302}
	ctx.JA4Exts = []uint16{0x001b}
	ctx.JA4ALPN = "h2"
	ctx.JA4Protocol = "t"
	ctx.JA4SNI = true
	ctx.JA4Ver = 0x0304
	defer ReleaseContext(ctx)

	event := NewEvent(ctx, 200)

	if event.TLSVersion != "TLS 1.2" {
		t.Errorf("expected TLS 1.2, got %q", event.TLSVersion)
	}
	if event.TLSCipherSuite != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
		t.Errorf("expected TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, got %q", event.TLSCipherSuite)
	}
	if event.ServerName != "example.com" {
		t.Errorf("expected ServerName example.com, got %q", event.ServerName)
	}
	if event.JA4Fingerprint == "" {
		t.Error("expected JA4 fingerprint to be set")
	}
}

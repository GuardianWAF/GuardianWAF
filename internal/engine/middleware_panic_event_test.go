package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// Regression tests for the Middleware panic path (round-12 fix, restored by
// the series diff review after a concurrent write wiped engine.go): a panic
// in the wrapped handler must be recovered into a 500 (original behavior)
// AND record a minimal audit event, so attack-induced crashes are visible in
// the event trail. Recording failures must fall back to the bare-500
// behavior instead of crashing the server.

// panicCaptureStore is an in-package EventStorer mock. No internal/events
// import — engine in-package tests must not create that cycle.
type panicCaptureStore struct {
	mu            sync.Mutex
	events        []Event
	failWithPanic bool // Store panics when set (guard-flag test)
}

func (s *panicCaptureStore) Store(ev Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failWithPanic {
		panic("event store exploded")
	}
	s.events = append(s.events, ev)
	return nil
}

func (s *panicCaptureStore) Close() error { return nil }

// panicCaptureBus is an in-package EventPublisher mock.
type panicCaptureBus struct {
	mu        sync.Mutex
	published []Event
}

func (b *panicCaptureBus) Subscribe(chan<- Event) {}

func (b *panicCaptureBus) Publish(ev Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.published = append(b.published, ev)
}

func (b *panicCaptureBus) Close() {}

func newPanicTestEngine(t *testing.T, store *panicCaptureStore, bus *panicCaptureBus) *Engine {
	t.Helper()
	e, err := NewEngine(config.DefaultConfig(), store, bus)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func TestMiddleware_PanicRecordsEvent(t *testing.T) {
	store := &panicCaptureStore{}
	bus := &panicCaptureBus{}
	e := newPanicTestEngine(t, store, bus)

	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom: attack-induced crash")
	})
	srv := httptest.NewServer(e.Middleware(panicHandler))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/crash?x=1")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("FAIL: status = %d, want 500 — recovery must keep the original response behavior", resp.StatusCode)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	// Two events are expected for a panicking request: the normal pipeline
	// event (recorded before the handler runs) plus the crash event added by
	// recordPanicEvent. Exactly one of them must be the 500 crash event.
	var crashEvents []Event
	for _, ev := range store.events {
		if ev.StatusCode == http.StatusInternalServerError {
			crashEvents = append(crashEvents, ev)
		}
	}
	if len(crashEvents) != 1 {
		t.Fatalf("FAIL: panicked request produced %d crash events (500), want exactly 1; all events: %+v", len(crashEvents), store.events)
	}
	ev := crashEvents[0]
	if ev.Action != ActionLog {
		t.Errorf("FAIL: crash event action = %v, want ActionLog", ev.Action)
	}
	if ev.Path != "/crash" {
		t.Errorf("FAIL: event path = %q, want %q", ev.Path, "/crash")
	}
	if ev.RequestID == "" {
		t.Errorf("FAIL: event request id empty — correlation header set before the handler should be carried into the panic event")
	}
	if len(ev.Findings) != 1 || ev.Findings[0].DetectorName != "panic-recovered" {
		t.Errorf("FAIL: findings = %+v, want a single panic-recovered finding", ev.Findings)
	} else if !strings.Contains(ev.Findings[0].MatchedValue, "boom") {
		t.Errorf("FAIL: matched value = %q, want it to contain the panic value", ev.Findings[0].MatchedValue)
	}

	bus.mu.Lock()
	defer bus.mu.Unlock()
	var publishedCrashes int
	for _, ev := range bus.published {
		if ev.StatusCode == http.StatusInternalServerError {
			publishedCrashes++
		}
	}
	if publishedCrashes != 1 {
		t.Errorf("FAIL: bus published %d crash events, want 1", publishedCrashes)
	}
}

func TestMiddleware_NormalRequestStillRecordsEvent(t *testing.T) {
	store := &panicCaptureStore{}
	bus := &panicCaptureBus{}
	e := newPanicTestEngine(t, store, bus)

	srv := httptest.NewServer(e.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/ok")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("FAIL: status = %d, want 200", resp.StatusCode)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.events) != 1 {
		t.Fatalf("FAIL: normal request produced %d audit events, want exactly 1", len(store.events))
	}
	if store.events[0].StatusCode != http.StatusOK {
		t.Errorf("FAIL: normal event status code = %d, want 200", store.events[0].StatusCode)
	}
}

func TestMiddleware_PanicEventRecordingFailureFallsBack(t *testing.T) {
	store := &panicCaptureStore{failWithPanic: true}
	bus := &panicCaptureBus{}
	e := newPanicTestEngine(t, store, bus)

	srv := httptest.NewServer(e.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("double trouble")
	})))
	defer srv.Close()

	// Two panicking requests: the first recording attempt panics inside the
	// store; the guard flag must disable further attempts, and both requests
	// must still be recovered into a clean 500.
	for i := 0; i < 2; i++ {
		resp, err := http.Get(srv.URL + "/crash")
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("FAIL: request %d status = %d, want 500 (recording failure must fall back to the original behavior)", i, resp.StatusCode)
		}
	}

	if !e.panicEventBroken.Load() {
		t.Error("FAIL: panicEventBroken guard flag not set after a recording panic")
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.events) != 0 {
		t.Errorf("FAIL: store recorded %d events, want 0 (Store panics; guard must prevent repeated attempts)", len(store.events))
	}
}

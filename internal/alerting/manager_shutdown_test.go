package alerting

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestManager_CloseWithContextWaitsForInFlightWebhook(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var startedClosed atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if startedClosed.CompareAndSwap(false, true) {
			close(started)
		}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := NewManager([]WebhookTarget{{
		Name:   "slow",
		URL:    srv.URL,
		Type:   "generic",
		Events: []string{"block"},
	}})

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("webhook request did not start")
	}

	done := make(chan error, 1)
	go func() {
		done <- m.CloseWithContext(context.Background())
	}()

	select {
	case err := <-done:
		t.Fatalf("CloseWithContext returned before in-flight webhook completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("CloseWithContext returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("CloseWithContext did not return after webhook completed")
	}
}

func TestManager_CloseWithContextTimeout(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var startedClosed atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if startedClosed.CompareAndSwap(false, true) {
			close(started)
		}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := NewManager([]WebhookTarget{{
		Name:   "slow",
		URL:    srv.URL,
		Type:   "generic",
		Events: []string{"block"},
	}})

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("webhook request did not start")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := m.CloseWithContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline exceeded, got %v", err)
	}

	close(release)
	if err := m.CloseWithContext(context.Background()); err != nil {
		t.Fatalf("final CloseWithContext returned error: %v", err)
	}
}

func TestManager_ClosePreventsNewDispatch(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := NewManager([]WebhookTarget{{
		Name:   "closed",
		URL:    srv.URL,
		Type:   "generic",
		Events: []string{"block"},
	}})
	if err := m.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	m.HandleEvent(testEvent(engine.ActionBlock, 80, "1.2.3.4"))
	time.Sleep(50 * time.Millisecond)
	if got := requests.Load(); got != 0 {
		t.Fatalf("closed manager dispatched %d requests", got)
	}
}

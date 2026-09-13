package events

import (
	"net/http"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (round 73): NewPersistentMemoryStore documents an empty-path
// fallback to "a plain MemoryStore (no persistence)", but Store()'s
// handle-less recovery branch unconditionally attempted
// os.OpenFile(ps.path, ...) — with an empty path that syscall fails on every
// call and incremented ps.dropped, so a memory-only store reported a 100%
// drop rate (DroppedEvents() == number of accepted events) to DropReporter
// consumers and burned a doomed syscall per event. The recovery branch is now
// skipped for stores constructed without a path.

func memoryOnlyFixture(t *testing.T, n int) *PersistentMemoryStore {
	t.Helper()
	ps, err := NewPersistentMemoryStore(10, "")
	if err != nil {
		t.Fatalf("NewPersistentMemoryStore with empty path: %v", err)
	}
	for i := 0; i < n; i++ {
		ev := engine.Event{
			ID:        time.Now().Format("20060102150405.000000000") + "-" + http.MethodGet,
			Timestamp: time.Now(),
			Method:    http.MethodGet,
			Path:      "/memory-only",
			Action:    engine.ActionBlock,
			Score:     50,
		}
		if err := ps.Store(ev); err != nil {
			t.Fatalf("Store into memory-only store: %v", err)
		}
	}
	return ps
}

func TestPersistentMemoryStore_EmptyPathIsMemoryOnly(t *testing.T) {
	ps := memoryOnlyFixture(t, 3)

	// The constructor documents "no persistence" for an empty path: nothing
	// can be dropped, so the drop counter must stay at zero.
	if d := ps.DroppedEvents(); d != 0 {
		t.Fatalf("memory-only store reported %d dropped events; the empty-path fallback drops nothing (pre-fix: every accepted event was counted via a doomed OpenFile(\"\"))", d)
	}

	recent, err := ps.Recent(10)
	if err != nil || len(recent) != 3 {
		t.Fatalf("memory-only store events: got %d of 3 (err=%v)", len(recent), err)
	}
	if _, err := ps.Get(recent[0].ID); err != nil {
		t.Fatalf("Get on memory-only store: %v", err)
	}
}

// Boundary: the empty-path fallback must keep honouring the closed-store
// contract — Close() followed by Store() returns an error instead of
// silently succeeding.
func TestPersistentMemoryStore_MemoryOnlyCloseThenStoreFails(t *testing.T) {
	ps := memoryOnlyFixture(t, 1)
	if err := ps.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ev := engine.Event{ID: "after-close", Timestamp: time.Now()}
	if err := ps.Store(ev); err == nil {
		t.Fatal("Store after Close on the memory-only fallback returned nil; want the closed-store error")
	}
}

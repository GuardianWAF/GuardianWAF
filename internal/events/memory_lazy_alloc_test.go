package events

import (
	"fmt"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// A large-capacity store must not allocate its full ring up front: the
// default 100,000-event capacity used to cost ~44 MB per engine at startup.
func TestMemoryStoreAllocatesLazily(t *testing.T) {
	ms := NewMemoryStore(100000)
	for i, c := range ms.chunks {
		if c != nil {
			t.Fatalf("chunk %d allocated before any event was stored", i)
		}
	}
	_ = ms.Store(engine.Event{ID: "first"})
	allocated := 0
	for _, c := range ms.chunks {
		allocated += len(c)
	}
	if allocated != memoryChunkSize {
		t.Fatalf("one stored event allocated %d slots, want one chunk (%d)", allocated, memoryChunkSize)
	}
}

// Ring semantics are unchanged across the grow-then-wrap transition.
func TestMemoryStoreLazyRingSemantics(t *testing.T) {
	const capacity = memoryChunkSize*2 + 7 // partial last chunk
	ms := NewMemoryStore(capacity)
	total := capacity*2 + 3
	for i := range total {
		if err := ms.Store(engine.Event{ID: fmt.Sprintf("e%d", i), Score: i}); err != nil {
			t.Fatal(err)
		}
		// Check the invariants at a few points before and after wrapping.
		if i == 10 || i == capacity-1 || i == capacity || i == total-1 {
			wantCount := min(i+1, capacity)
			recent, _ := ms.Recent(wantCount + 5)
			if len(recent) != wantCount {
				t.Fatalf("after %d stores Recent returned %d, want %d", i+1, len(recent), wantCount)
			}
			for j, ev := range recent {
				if want := fmt.Sprintf("e%d", i-j); ev.ID != want {
					t.Fatalf("after %d stores Recent[%d] = %s, want %s", i+1, j, ev.ID, want)
				}
			}
			all, n, _ := ms.Query(EventFilter{SortBy: "score", SortOrder: "asc"})
			if n != wantCount || all[0].Score != i+1-wantCount {
				t.Fatalf("after %d stores Query returned %d events from score %d", i+1, n, all[0].Score)
			}
		}
	}
	slots := 0
	for _, c := range ms.chunks {
		slots += len(c)
	}
	if slots != capacity {
		t.Fatalf("allocated %d slots once full, want exactly capacity %d", slots, capacity)
	}
	if _, err := ms.Get("e0"); err == nil {
		t.Fatal("overwritten event is still retrievable")
	}
	if ev, err := ms.Get(fmt.Sprintf("e%d", total-1)); err != nil || ev.Score != total-1 {
		t.Fatalf("Get(latest) = %+v, %v", ev, err)
	}
	if len(ms.index) != capacity {
		t.Fatalf("index holds %d ids, want %d", len(ms.index), capacity)
	}
}

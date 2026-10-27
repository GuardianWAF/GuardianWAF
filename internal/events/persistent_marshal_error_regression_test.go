package events

import (
	"fmt"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"path/filepath"
	"testing"
	"time"
)

func TestPersistentMemoryStoreHandlesMarshalFailureWithoutLogger(t *testing.T) {
	for _, persist := range []bool{true, false} {
		path := ""
		if persist {
			path = filepath.Join(t.TempDir(), "events.jsonl")
		}
		ps, err := NewPersistentMemoryStore(10, path)
		if err != nil {
			t.Fatal(err)
		}
		defer ps.Close()
		for _, year := range []int{-1, 10000, 10001} {
			err := ps.Store(engine.Event{ID: fmt.Sprint(year), Timestamp: time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)})
			if err != nil {
				t.Fatalf("EXPECTED: counted drop without panic | ACTUAL: %v", err)
			}
			if _, err := ps.Get(fmt.Sprint(year)); err == nil {
				t.Fatal("rejected event stored")
			}
		}
		if ps.DroppedEvents() != 3 {
			t.Fatalf("drops=%d", ps.DroppedEvents())
		}
		for _, year := range []int{0, 2026, 9999} {
			if err := ps.Store(engine.Event{ID: fmt.Sprint(year), Timestamp: time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)}); err != nil {
				t.Fatal(err)
			}
		}
		got, err := ps.Recent(10)
		if err != nil || len(got) != 3 {
			t.Fatalf("recent=%v err=%v", got, err)
		}
		if persist {
			if err := ps.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := NewPersistentMemoryStore(10, path)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			got, err = reopened.Recent(10)
			if err != nil || len(got) != 3 {
				t.Fatalf("replay=%v err=%v", got, err)
			}
		}
	}
}

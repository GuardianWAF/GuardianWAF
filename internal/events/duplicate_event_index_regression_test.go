package events

import (
	"fmt"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"testing"
)

func TestMemoryStoreRetainsDuplicateIndex(t *testing.T) {
	for _, capacity := range []int{1, 2, 3} {
		for _, id := range []string{"same", ""} {
			t.Run(fmt.Sprintf("%d/%s", capacity, id), func(t *testing.T) {
				store := NewMemoryStore(capacity)
				var retained []engine.Event
				for i := range 15 {
					key := id
					if i%3 == 2 {
						key = fmt.Sprintf("other%d", i)
					}
					ev := engine.Event{ID: key, Path: fmt.Sprint(i)}
					_ = store.Store(ev)
					retained = append(retained, ev)
					if len(retained) > capacity {
						retained = retained[1:]
					}
					newest := map[string]string{}
					for _, r := range retained {
						newest[r.ID] = r.Path
					}
					for key, want := range newest {
						got, err := store.Get(key)
						if err != nil || got.Path != want {
							t.Fatalf("Get(%q)=%v,%v want %q", key, got, err, want)
						}
					}
					recent, err := store.Recent(20)
					if err != nil || len(recent) != len(retained) {
						t.Fatal("ring count changed")
					}
				}
			})
		}
	}
	if !t.Failed() {
		t.Log("FIX VERIFIED")
	}
}

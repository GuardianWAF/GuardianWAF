package botdetect

import (
	"testing"
	"time"
)

func TestBehaviorAdvanceRetainsFractionalElapsedTime(t *testing.T) {
	base := time.Unix(100, 0)
	newTracker := func() *BehaviorTracker {
		bt := &BehaviorTracker{size: 3, buckets: make([]bucket, 3), lastTick: base}
		bt.buckets[0] = bucket{
			requests:  7,
			errors:    2,
			paths:     map[string]struct{}{"/ordinary": {}},
			timings:   []time.Duration{time.Millisecond},
			timestamp: base,
		}
		return bt
	}
	for _, steps := range [][]time.Duration{
		{time.Second, 3 * time.Second},
		{1600 * time.Millisecond, 3100 * time.Millisecond},
		{600 * time.Millisecond, 1200 * time.Millisecond, 1800 * time.Millisecond, 2400 * time.Millisecond, 3 * time.Second},
	} {
		bt := newTracker()
		for _, step := range steps {
			bt.advance(base.Add(step))
		}
		b := bt.buckets[0]
		if b.requests != 0 || b.errors != 0 || len(b.paths) != 0 || len(b.timings) != 0 {
			t.Fatalf("steps %v retain expired metrics: %+v", steps, b)
		}
		if !bt.lastTick.Equal(base.Add(3 * time.Second)) {
			t.Fatalf("steps %v: last tick=%v", steps, bt.lastTick)
		}
	}
	t.Run("partial and backward time", func(t *testing.T) {
		bt := newTracker()
		for _, step := range []time.Duration{0, -time.Second, 600 * time.Millisecond} {
			bt.advance(base.Add(step))
			if bt.current != 0 || !bt.lastTick.Equal(base) || bt.buckets[0].requests != 7 {
				t.Fatalf("step %v unexpectedly advanced tracker", step)
			}
		}
		bt.advance(base.Add(1600 * time.Millisecond))
		if bt.current != 1 || !bt.lastTick.Equal(base.Add(time.Second)) || bt.buckets[0].requests != 7 {
			t.Fatal("first tick lost the remainder or cleared a live bucket")
		}
	})
	t.Run("gap larger than ring", func(t *testing.T) {
		bt := newTracker()
		bt.advance(base.Add(10600 * time.Millisecond))
		for _, b := range bt.buckets {
			if b.requests != 0 || b.errors != 0 || len(b.paths) != 0 || len(b.timings) != 0 {
				t.Fatalf("large gap retained metrics: %+v", b)
			}
		}
		if !bt.lastTick.Equal(base.Add(10 * time.Second)) {
			t.Fatal("capped clearing discarded the fractional remainder")
		}
		bt.advance(base.Add(11050 * time.Millisecond))
		if bt.current != 1 || !bt.lastTick.Equal(base.Add(11*time.Second)) {
			t.Fatal("advance after large gap drifted")
		}
	})
}

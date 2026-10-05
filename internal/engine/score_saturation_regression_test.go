package engine

import (
	"math"
	"testing"
)

func TestScoreAccumulatorSaturatesBeforeOverflow(t *testing.T) {
	for level := 1; level <= 4; level++ {
		for _, scores := range [][]int{{math.MaxInt}, {math.MaxInt, math.MaxInt}, {19999, 1, 1}, {0, -1, math.MaxInt}} {
			b := NewScoreAccumulator(level)
			previous := 0
			for _, score := range scores {
				b.Add(&Finding{Score: score})
				got := b.Total()
				if got < previous || got > 10000 {
					t.Fatalf("level=%d score=%d total=%d previous=%d", level, score, got, previous)
				}
				previous = got
			}
			if b.Total() != 10000 {
				t.Fatalf("level=%d scores=%v total=%d", level, scores, b.Total())
			}
			if len(b.Findings()) != len(scores) {
				t.Fatal("findings lost")
			}
			b.Reset()
			b.Add(&Finding{Score: 2})
			if b.Total() != int(2*paranoiaToMultiplier(level)) {
				t.Fatal("reset/multiplier changed")
			}
		}
	}
	t.Log("FIX VERIFIED")
}

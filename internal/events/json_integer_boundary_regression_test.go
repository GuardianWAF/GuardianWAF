package events

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"testing"
)

func TestFileJSONIntegerBoundaries(t *testing.T) {
	for _, n := range []int64{math.MinInt64, math.MinInt64 + 1, -1, 0, 1, math.MaxInt64} {
		var b strings.Builder
		writeJSONInt64(&b, n)
		if want := strconv.FormatInt(n, 10); b.String() != want {
			t.Fatalf("n=%d got=%q want=%q", n, b.String(), want)
		}
		var got int64
		if err := json.Unmarshal([]byte(b.String()), &got); err != nil || got != n {
			t.Fatalf("JSON roundtrip: got=%d err=%v", got, err)
		}
	}
	t.Log("FIX VERIFIED")
}

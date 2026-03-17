package analytics

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Counter tests
// ---------------------------------------------------------------------------

func TestCounterAddAndTotal(t *testing.T) {
	c := NewCounter(10*time.Second, 1*time.Second)

	c.Add(5)
	c.Add(3)

	total := c.Total()
	if total != 8 {
		t.Fatalf("expected total 8, got %d", total)
	}
}

func TestCounterReset(t *testing.T) {
	c := NewCounter(10*time.Second, 1*time.Second)
	c.Add(100)
	c.Reset()

	if total := c.Total(); total != 0 {
		t.Fatalf("expected 0 after reset, got %d", total)
	}
}

func TestCounterNewDefaults(t *testing.T) {
	// step > window should default to window
	c := NewCounter(5*time.Second, 10*time.Second)
	c.Add(1)
	if c.Total() != 1 {
		t.Fatalf("expected 1, got %d", c.Total())
	}

	// zero step
	c2 := NewCounter(5*time.Second, 0)
	c2.Add(42)
	if c2.Total() != 42 {
		t.Fatalf("expected 42, got %d", c2.Total())
	}
}

func TestCounterMultipleBuckets(t *testing.T) {
	c := NewCounter(4*time.Second, 1*time.Second)
	// Add to the initial bucket
	c.Add(10)

	total := c.Total()
	if total != 10 {
		t.Fatalf("expected 10, got %d", total)
	}
}

// ---------------------------------------------------------------------------
// TopK tests
// ---------------------------------------------------------------------------

func TestTopKAdd(t *testing.T) {
	tk := NewTopK(3)

	tk.Add("a", 10)
	tk.Add("b", 20)
	tk.Add("c", 5)
	tk.Add("d", 15)

	top := tk.Top()
	if len(top) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(top))
	}

	if top[0].Key != "b" || top[0].Count != 20 {
		t.Fatalf("expected top entry b:20, got %s:%d", top[0].Key, top[0].Count)
	}
	if top[1].Key != "d" || top[1].Count != 15 {
		t.Fatalf("expected second entry d:15, got %s:%d", top[1].Key, top[1].Count)
	}
	if top[2].Key != "a" || top[2].Count != 10 {
		t.Fatalf("expected third entry a:10, got %s:%d", top[2].Key, top[2].Count)
	}
}

func TestTopKIncrement(t *testing.T) {
	tk := NewTopK(5)
	tk.Add("x", 1)
	tk.Add("x", 1)
	tk.Add("x", 1)

	if c := tk.Count("x"); c != 3 {
		t.Fatalf("expected count 3, got %d", c)
	}
}

func TestTopKReset(t *testing.T) {
	tk := NewTopK(5)
	tk.Add("a", 10)
	tk.Reset()

	if len(tk.Top()) != 0 {
		t.Fatal("expected empty after reset")
	}
}

func TestTopKDefaultK(t *testing.T) {
	tk := NewTopK(0)
	for i := 0; i < 20; i++ {
		tk.Add(string(rune('a'+i)), int64(i))
	}
	top := tk.Top()
	if len(top) != 10 {
		t.Fatalf("expected 10 (default k), got %d", len(top))
	}
}

// ---------------------------------------------------------------------------
// TimeSeries tests
// ---------------------------------------------------------------------------

func TestTimeSeriesAddAndPoints(t *testing.T) {
	ts := NewTimeSeries(5)

	now := time.Now()
	for i := 0; i < 5; i++ {
		ts.Add(now.Add(time.Duration(i)*time.Second), float64(i))
	}

	points := ts.Points()
	if len(points) != 5 {
		t.Fatalf("expected 5 points, got %d", len(points))
	}

	// Should be chronological
	for i := 0; i < 5; i++ {
		if points[i].Value != float64(i) {
			t.Fatalf("point %d: expected value %f, got %f", i, float64(i), points[i].Value)
		}
	}
}

func TestTimeSeriesOverflow(t *testing.T) {
	ts := NewTimeSeries(3)

	now := time.Now()
	for i := 0; i < 5; i++ {
		ts.Add(now.Add(time.Duration(i)*time.Second), float64(i))
	}

	points := ts.Points()
	if len(points) != 3 {
		t.Fatalf("expected 3 points, got %d", len(points))
	}

	// Should have the last 3: 2, 3, 4
	expected := []float64{2, 3, 4}
	for i, exp := range expected {
		if points[i].Value != exp {
			t.Fatalf("point %d: expected %f, got %f", i, exp, points[i].Value)
		}
	}
}

func TestTimeSeriesLast(t *testing.T) {
	ts := NewTimeSeries(10)

	_, ok := ts.Last()
	if ok {
		t.Fatal("expected no last point for empty series")
	}

	now := time.Now()
	ts.Add(now, 42.0)

	pt, ok := ts.Last()
	if !ok {
		t.Fatal("expected last point")
	}
	if pt.Value != 42.0 {
		t.Fatalf("expected 42.0, got %f", pt.Value)
	}
}

func TestTimeSeriesLen(t *testing.T) {
	ts := NewTimeSeries(5)
	if ts.Len() != 0 {
		t.Fatalf("expected 0, got %d", ts.Len())
	}

	now := time.Now()
	ts.Add(now, 1)
	ts.Add(now, 2)

	if ts.Len() != 2 {
		t.Fatalf("expected 2, got %d", ts.Len())
	}
}

func TestTimeSeriesReset(t *testing.T) {
	ts := NewTimeSeries(5)
	now := time.Now()
	ts.Add(now, 1)
	ts.Add(now, 2)
	ts.Reset()

	if ts.Len() != 0 {
		t.Fatalf("expected 0 after reset, got %d", ts.Len())
	}
	if pts := ts.Points(); pts != nil {
		t.Fatalf("expected nil points after reset, got %v", pts)
	}
}

func TestTimeSeriesDefaultSize(t *testing.T) {
	ts := NewTimeSeries(0)
	// default should be 60
	now := time.Now()
	for i := 0; i < 100; i++ {
		ts.Add(now.Add(time.Duration(i)*time.Second), float64(i))
	}
	if ts.Len() != 60 {
		t.Fatalf("expected 60, got %d", ts.Len())
	}
}

func TestTimeSeriesEmptyPoints(t *testing.T) {
	ts := NewTimeSeries(5)
	if pts := ts.Points(); pts != nil {
		t.Fatalf("expected nil for empty series, got %v", pts)
	}
}

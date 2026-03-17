package analytics

import (
	"sync"
	"time"
)

// TimePoint is a single data point in a time series.
type TimePoint struct {
	Timestamp time.Time
	Value     float64
}

// TimeSeries is a fixed-size ring buffer of time-stamped data points.
// It stores the most recent `size` points, overwriting the oldest when full.
type TimeSeries struct {
	mu      sync.Mutex
	buckets []TimePoint
	size    int
	head    int // next write position
	count   int
}

// NewTimeSeries creates a TimeSeries that holds at most size data points.
// If size < 1, it defaults to 60.
func NewTimeSeries(size int) *TimeSeries {
	if size < 1 {
		size = 60
	}
	return &TimeSeries{
		buckets: make([]TimePoint, size),
		size:    size,
	}
}

// Add appends a data point. When the buffer is full, the oldest point is overwritten.
func (ts *TimeSeries) Add(t time.Time, v float64) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	ts.buckets[ts.head] = TimePoint{Timestamp: t, Value: v}
	ts.head = (ts.head + 1) % ts.size
	if ts.count < ts.size {
		ts.count++
	}
}

// Points returns all stored data points in chronological order (oldest first).
func (ts *TimeSeries) Points() []TimePoint {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.count == 0 {
		return nil
	}

	result := make([]TimePoint, ts.count)
	for i := 0; i < ts.count; i++ {
		pos := (ts.head - ts.count + i + ts.size) % ts.size
		result[i] = ts.buckets[pos]
	}
	return result
}

// Last returns the most recently added point, or a zero TimePoint if empty.
func (ts *TimeSeries) Last() (TimePoint, bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.count == 0 {
		return TimePoint{}, false
	}
	pos := (ts.head - 1 + ts.size) % ts.size
	return ts.buckets[pos], true
}

// Len returns the number of stored data points.
func (ts *TimeSeries) Len() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.count
}

// Reset clears all data points.
func (ts *TimeSeries) Reset() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.count = 0
	ts.head = 0
}

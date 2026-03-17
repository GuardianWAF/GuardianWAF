// Package analytics provides rolling-window counters, top-K tracking,
// and time-series ring buffers for GuardianWAF metrics.
package analytics

import (
	"sync"
	"time"
)

// Counter tracks a value over rolling time windows.
// It divides the window into equal-sized steps (buckets) and rotates
// old buckets as time advances, giving an approximate rolling total.
type Counter struct {
	mu       sync.Mutex
	buckets  []int64
	window   time.Duration
	step     time.Duration
	current  int
	lastTick time.Time
}

// NewCounter creates a Counter with the given total window and step size.
// The window is divided into (window/step) buckets. If step is zero or
// larger than window, it defaults to window (single bucket).
func NewCounter(window, step time.Duration) *Counter {
	if step <= 0 || step > window {
		step = window
	}
	n := int(window / step)
	if n < 1 {
		n = 1
	}
	return &Counter{
		buckets:  make([]int64, n),
		window:   window,
		step:     step,
		current:  0,
		lastTick: time.Now(),
	}
}

// advance rotates buckets forward to account for elapsed time.
func (c *Counter) advance() {
	now := time.Now()
	elapsed := now.Sub(c.lastTick)
	if elapsed < c.step {
		return
	}

	steps := int(elapsed / c.step)
	if steps >= len(c.buckets) {
		// Entire window has passed; clear everything
		for i := range c.buckets {
			c.buckets[i] = 0
		}
		c.current = 0
		c.lastTick = now
		return
	}

	for i := 0; i < steps; i++ {
		c.current = (c.current + 1) % len(c.buckets)
		c.buckets[c.current] = 0
	}
	c.lastTick = now
}

// Add increments the current bucket by n.
func (c *Counter) Add(n int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.advance()
	c.buckets[c.current] += n
}

// Total returns the sum of all buckets in the rolling window.
func (c *Counter) Total() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.advance()

	var total int64
	for _, v := range c.buckets {
		total += v
	}
	return total
}

// Reset zeroes all buckets.
func (c *Counter) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.buckets {
		c.buckets[i] = 0
	}
	c.current = 0
	c.lastTick = time.Now()
}

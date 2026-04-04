// Package analytics provides metrics collection and analysis for GuardianWAF.
package analytics

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// MetricType represents the type of metric.
type MetricType string

const (
	TypeCounter   MetricType = "counter"
	TypeGauge     MetricType = "gauge"
	TypeHistogram MetricType = "histogram"
)

// Metric represents a collected metric.
type Metric struct {
	Name      string            `json:"name"`
	Type      MetricType        `json:"type"`
	Value     float64           `json:"value"`
	Labels    map[string]string `json:"labels,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// TimeSeriesPoint represents a single data point in time.
type TimeSeriesPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// TimeSeries represents a series of metrics over time.
type TimeSeries struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
	Points []TimeSeriesPoint `json:"points"`
}

// Collector manages metrics collection.
type Collector struct {
	counters   map[string]*atomic.Int64
	gauges     map[string]*GaugeValue
	histograms map[string]*Histogram
	series     map[string]*TimeSeriesBuffer
	mu         sync.RWMutex
	config     *Config
}

// GaugeValue holds a float64 gauge value.
type GaugeValue struct {
	mu    sync.RWMutex
	value float64
}

// Store sets the gauge value.
func (g *GaugeValue) Store(v float64) {
	g.mu.Lock()
	g.value = v
	g.mu.Unlock()
}

// Load returns the gauge value.
func (g *GaugeValue) Load() float64 {
	g.mu.RLock()
	v := g.value
	g.mu.RUnlock()
	return v
}

// Config for analytics collector.
type Config struct {
	Enabled         bool          `yaml:"enabled"`
	StoragePath     string        `yaml:"storage_path"`
	RetentionDays   int           `yaml:"retention_days"`
	FlushInterval   time.Duration `yaml:"flush_interval"`
	MaxDataPoints   int           `yaml:"max_data_points"`
	EnableTimeSeries bool         `yaml:"enable_time_series"`
}

// DefaultConfig returns default collector config.
func DefaultConfig() *Config {
	return &Config{
		Enabled:          true,
		StoragePath:      "data/analytics",
		RetentionDays:    30,
		FlushInterval:    60 * time.Second,
		MaxDataPoints:    10000,
		EnableTimeSeries: true,
	}
}

// Histogram tracks distribution of values.
type Histogram struct {
	Name       string
	Buckets    []float64
	Counts     []int64
	Sum        atomic.Int64
	Count      atomic.Int64
	Min        atomic.Int64
	Max        atomic.Int64
}

// NewHistogram creates a new histogram.
func NewHistogram(name string, buckets []float64) *Histogram {
	if len(buckets) == 0 {
		// Default buckets for latency
		buckets = []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}
	}
	h := &Histogram{
		Name:    name,
		Buckets: buckets,
		Counts:  make([]int64, len(buckets)+1),
	}
	h.Min.Store(int64(math.MaxInt64))
	h.Max.Store(0)
	return h
}

// Record records a value in the histogram.
func (h *Histogram) Record(value float64) {
	val := int64(value)
	h.Sum.Add(val)
	h.Count.Add(1)

	// Update min/max
	for {
		old := h.Min.Load()
		if val >= old || h.Min.CompareAndSwap(old, val) {
			break
		}
	}
	for {
		old := h.Max.Load()
		if val <= old || h.Max.CompareAndSwap(old, val) {
			break
		}
	}

	// Find bucket
	for i, bucket := range h.Buckets {
		if value <= bucket {
			h.Counts[i]++
			return
		}
	}
	h.Counts[len(h.Buckets)]++ // +Inf bucket
}

// Snapshot returns current histogram statistics.
func (h *Histogram) Snapshot() HistogramSnapshot {
	count := h.Count.Load()
	if count == 0 {
		return HistogramSnapshot{}
	}

	sum := h.Sum.Load()
	min := h.Min.Load()
	if min == math.MaxInt64 {
		min = 0
	}

	return HistogramSnapshot{
		Name:   h.Name,
		Count:  count,
		Sum:    float64(sum),
		Min:    float64(min),
		Max:    float64(h.Max.Load()),
		Mean:   float64(sum) / float64(count),
		Buckets: h.Buckets,
		Counts:  h.Counts,
	}
}

// HistogramSnapshot represents histogram data.
type HistogramSnapshot struct {
	Name    string    `json:"name"`
	Count   int64     `json:"count"`
	Sum     float64   `json:"sum"`
	Min     float64   `json:"min"`
	Max     float64   `json:"max"`
	Mean    float64   `json:"mean"`
	Buckets []float64 `json:"buckets"`
	Counts  []int64   `json:"counts"`
}

// TimeSeriesBuffer manages time series data.
type TimeSeriesBuffer struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
	Points []TimeSeriesPoint `json:"points"`
	mu     sync.RWMutex
	maxLen int
}

// NewTimeSeriesBuffer creates a new time series buffer.
func NewTimeSeriesBuffer(name string, labels map[string]string, maxPoints int) *TimeSeriesBuffer {
	return &TimeSeriesBuffer{
		Name:   name,
		Labels: labels,
		Points: make([]TimeSeriesPoint, 0, maxPoints),
		maxLen: maxPoints,
	}
}

// Add adds a point to the series.
func (ts *TimeSeriesBuffer) Add(value float64) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	point := TimeSeriesPoint{
		Timestamp: time.Now(),
		Value:     value,
	}

	ts.Points = append(ts.Points, point)

	// Remove old points if exceeding max
	if len(ts.Points) > ts.maxLen {
		ts.Points = ts.Points[len(ts.Points)-ts.maxLen:]
	}
}

// GetPoints returns points within time range.
func (ts *TimeSeriesBuffer) GetPoints(from, to time.Time) []TimeSeriesPoint {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	var result []TimeSeriesPoint
	for _, p := range ts.Points {
		if p.Timestamp.After(from) && p.Timestamp.Before(to) {
			result = append(result, p)
		}
	}
	return result
}

// NewCollector creates a new metrics collector.
func NewCollector(cfg *Config) *Collector {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	c := &Collector{
		counters:   make(map[string]*atomic.Int64),
		gauges:     make(map[string]*GaugeValue),
		histograms: make(map[string]*Histogram),
		series:     make(map[string]*TimeSeriesBuffer),
		config:     cfg,
	}

	// Ensure storage directory exists
	if cfg.StoragePath != "" {
		os.MkdirAll(cfg.StoragePath, 0755)
	}

	// Start background flush
	if cfg.FlushInterval > 0 {
		go c.flushLoop()
	}

	return c
}

// Counter increments a counter metric.
func (c *Collector) Counter(name string, labels map[string]string, value int64) {
	if !c.config.Enabled {
		return
	}

	key := metricKey(name, labels)

	c.mu.RLock()
	counter, exists := c.counters[key]
	c.mu.RUnlock()

	if !exists {
		c.mu.Lock()
		counter = &atomic.Int64{}
		c.counters[key] = counter
		c.mu.Unlock()
	}

	counter.Add(value)

	// Add to time series if enabled
	if c.config.EnableTimeSeries {
		c.addToSeries(key, float64(value))
	}
}

// Gauge sets a gauge metric.
func (c *Collector) Gauge(name string, labels map[string]string, value float64) {
	if !c.config.Enabled {
		return
	}

	key := metricKey(name, labels)

	c.mu.RLock()
	gauge, exists := c.gauges[key]
	c.mu.RUnlock()

	if !exists {
		c.mu.Lock()
		gauge = &GaugeValue{}
		c.gauges[key] = gauge
		c.mu.Unlock()
	}

	gauge.Store(value)

	if c.config.EnableTimeSeries {
		c.addToSeries(key, value)
	}
}

// Histogram records a histogram observation.
func (c *Collector) Histogram(name string, labels map[string]string, value float64) {
	if !c.config.Enabled {
		return
	}

	key := metricKey(name, labels)

	c.mu.RLock()
	hist, exists := c.histograms[key]
	c.mu.RUnlock()

	if !exists {
		c.mu.Lock()
		hist = NewHistogram(name, nil)
		c.histograms[key] = hist
		c.mu.Unlock()
	}

	hist.Record(value)
}

// addToSeries adds value to time series.
func (c *Collector) addToSeries(key string, value float64) {
	c.mu.RLock()
	ts, exists := c.series[key]
	c.mu.RUnlock()

	if !exists {
		c.mu.Lock()
		ts = NewTimeSeriesBuffer(key, nil, c.config.MaxDataPoints)
		c.series[key] = ts
		c.mu.Unlock()
	}

	ts.Add(value)
}

// GetCounter returns counter value.
func (c *Collector) GetCounter(name string, labels map[string]string) int64 {
	key := metricKey(name, labels)

	c.mu.RLock()
	counter, exists := c.counters[key]
	c.mu.RUnlock()

	if !exists {
		return 0
	}
	return counter.Load()
}

// GetGauge returns gauge value.
func (c *Collector) GetGauge(name string, labels map[string]string) float64 {
	key := metricKey(name, labels)

	c.mu.RLock()
	gauge, exists := c.gauges[key]
	c.mu.RUnlock()

	if !exists {
		return 0
	}
	return gauge.Load()
}

// GetHistogram returns histogram snapshot.
func (c *Collector) GetHistogram(name string, labels map[string]string) HistogramSnapshot {
	key := metricKey(name, labels)

	c.mu.RLock()
	hist, exists := c.histograms[key]
	c.mu.RUnlock()

	if !exists {
		return HistogramSnapshot{}
	}

	return hist.Snapshot()
}

// GetTimeSeries returns time series data.
func (c *Collector) GetTimeSeries(name string, labels map[string]string, from, to time.Time) *TimeSeries {
	key := metricKey(name, labels)

	c.mu.RLock()
	ts, exists := c.series[key]
	c.mu.RUnlock()

	if !exists {
		return nil
	}

	return &TimeSeries{
		Name:   name,
		Labels: labels,
		Points: ts.GetPoints(from, to),
	}
}

// GetAllMetrics returns all current metrics.
func (c *Collector) GetAllMetrics() map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := map[string]any{
		"counters":   make(map[string]int64),
		"gauges":     make(map[string]float64),
		"histograms": make(map[string]HistogramSnapshot),
	}

	for key, counter := range c.counters {
		result["counters"].(map[string]int64)[key] = counter.Load()
	}

	for key, gauge := range c.gauges {
		result["gauges"].(map[string]float64)[key] = gauge.Load()
	}

	for key, hist := range c.histograms {
		result["histograms"].(map[string]HistogramSnapshot)[key] = hist.Snapshot()
	}

	return result
}

// flushLoop periodically flushes metrics to disk.
func (c *Collector) flushLoop() {
	ticker := time.NewTicker(c.config.FlushInterval)
	defer ticker.Stop()

	for range ticker.C {
		c.Flush()
	}
}

// Flush writes metrics to storage.
func (c *Collector) Flush() error {
	if c.config.StoragePath == "" {
		return nil
	}

	c.mu.RLock()
	data := c.GetAllMetrics()
	c.mu.RUnlock()

	filename := filepath.Join(c.config.StoragePath, fmt.Sprintf("metrics-%s.json",
		time.Now().Format("YYYYMMDD")))

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// Reset clears all metrics.
func (c *Collector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.counters = make(map[string]*atomic.Int64)
	c.gauges = make(map[string]*GaugeValue)
	c.histograms = make(map[string]*Histogram)
	c.series = make(map[string]*TimeSeriesBuffer)
}

// Close stops the collector.
func (c *Collector) Close() error {
	return c.Flush()
}

// metricKey generates a unique key for metric with labels.
func metricKey(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name
	}

	// Sort labels for consistent key
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	key := name
	for _, k := range keys {
		key += fmt.Sprintf(";%s=%s", k, labels[k])
	}
	return key
}

// Percentile calculates the percentile from histogram.
func (h *HistogramSnapshot) Percentile(p float64) float64 {
	if h.Count == 0 {
		return 0
	}

	target := int64(float64(h.Count) * p / 100)
	var count int64

	for i, c := range h.Counts {
		count += c
		if count >= target {
			if i < len(h.Buckets) {
				return h.Buckets[i]
			}
			return h.Max
		}
	}

	return h.Max
}

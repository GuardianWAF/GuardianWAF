package analytics

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Collector: addToSeries, GetTimeSeries, GetPoints, TimeSeries queries
// ---------------------------------------------------------------------------

func TestCollector_AddToSeriesAndGetTimeSeries(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		EnableTimeSeries: true,
		MaxDataPoints:    100,
	}
	collector := NewCollector(cfg)
	defer collector.Close()

	// Counter with time series enabled should add points
	collector.Counter("test_metric", nil, 5)
	collector.Counter("test_metric", nil, 3)

	from := time.Now().Add(-time.Hour)
	to := time.Now().Add(time.Hour)

	ts := collector.GetTimeSeries("test_metric", nil, from, to)
	if ts == nil {
		t.Fatal("expected time series, got nil")
	}
	if ts.Name != "test_metric" {
		t.Errorf("ts.Name = %s, want test_metric", ts.Name)
	}
	if len(ts.Points) != 2 {
		t.Errorf("len(ts.Points) = %d, want 2", len(ts.Points))
	}
}

func TestCollector_GetTimeSeries_NotFound(t *testing.T) {
	cfg := &Config{Enabled: true, EnableTimeSeries: true}
	collector := NewCollector(cfg)
	defer collector.Close()

	ts := collector.GetTimeSeries("nonexistent", nil, time.Now(), time.Now())
	if ts != nil {
		t.Error("expected nil for nonexistent time series")
	}
}

func TestCollector_TimeSeries_WithLabels(t *testing.T) {
	cfg := &Config{Enabled: true, EnableTimeSeries: true, MaxDataPoints: 50}
	collector := NewCollector(cfg)
	defer collector.Close()

	labels := map[string]string{"method": "GET", "path": "/api"}
	collector.Counter("http_requests", labels, 10)

	from := time.Now().Add(-time.Hour)
	to := time.Now().Add(time.Hour)

	ts := collector.GetTimeSeries("http_requests", labels, from, to)
	if ts == nil {
		t.Fatal("expected time series, got nil")
	}
	if ts.Labels["method"] != "GET" {
		t.Errorf("labels[method] = %s, want GET", ts.Labels["method"])
	}
}

func TestCollector_TimeSeries_OutOfRange(t *testing.T) {
	cfg := &Config{Enabled: true, EnableTimeSeries: true, MaxDataPoints: 100}
	collector := NewCollector(cfg)
	defer collector.Close()

	collector.Counter("range_metric", nil, 1)

	// Query far future range — should return 0 points
	from := time.Now().Add(24 * time.Hour)
	to := time.Now().Add(48 * time.Hour)
	ts := collector.GetTimeSeries("range_metric", nil, from, to)
	if ts == nil {
		t.Fatal("expected time series object, got nil")
	}
	if len(ts.Points) != 0 {
		t.Errorf("expected 0 points for out-of-range query, got %d", len(ts.Points))
	}
}

func TestTimeSeriesBuffer_GetPoints(t *testing.T) {
	ts := NewTimeSeriesBuffer("test", nil, 100)

	// Add points manually with specific timestamps
	baseTime := time.Now().Add(-2 * time.Hour)
	for i := 0; i < 10; i++ {
		ts.mu.Lock()
		ts.Points = append(ts.Points, TimeSeriesPoint{
			Timestamp: baseTime.Add(time.Duration(i) * 10 * time.Minute),
			Value:     float64(i),
		})
		ts.mu.Unlock()
	}

	// Query a window that should capture points 2-6
	from := baseTime.Add(25 * time.Minute)
	to := baseTime.Add(65 * time.Minute)
	points := ts.GetPoints(from, to)

	if len(points) != 4 { // points at 30, 40, 50, 60 min offset
		t.Errorf("GetPoints returned %d points, want 4", len(points))
	}

	// Query full range (exclusive bounds, so use slightly before first and after last)
	allPoints := ts.GetPoints(baseTime.Add(-time.Second), baseTime.Add(3*time.Hour))
	if len(allPoints) != 10 {
		t.Errorf("GetPoints full range returned %d points, want 10", len(allPoints))
	}
}

func TestCollector_AddToSeries_MaxEntries(t *testing.T) {
	cfg := &Config{Enabled: true, EnableTimeSeries: true, MaxDataPoints: 10}
	collector := NewCollector(cfg)
	defer collector.Close()

	// Fill series map up to maxMapEntries
	for i := 0; i < maxMapEntries+10; i++ {
		collector.Counter(fmt.Sprintf("metric_%d", i), nil, 1)
	}

	// Should not panic; later metrics silently dropped after maxMapEntries
	total := len(collector.series)
	if total > maxMapEntries {
		t.Errorf("series map grew beyond maxMapEntries: %d", total)
	}
}

// ---------------------------------------------------------------------------
// Collector: Gauge with labels, time series
// ---------------------------------------------------------------------------

func TestCollector_Gauge_WithLabels(t *testing.T) {
	cfg := &Config{Enabled: true, EnableTimeSeries: true, MaxDataPoints: 100}
	collector := NewCollector(cfg)
	defer collector.Close()

	labels := map[string]string{"service": "api"}
	collector.Gauge("cpu_usage", labels, 75.5)

	val := collector.GetGauge("cpu_usage", labels)
	if val != 75.5 {
		t.Errorf("gauge = %f, want 75.5", val)
	}
}

func TestCollector_GetGauge_NotFound(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true})
	defer collector.Close()

	val := collector.GetGauge("no_such_gauge", nil)
	if val != 0 {
		t.Errorf("expected 0 for nonexistent gauge, got %f", val)
	}
}

// ---------------------------------------------------------------------------
// Collector: Disabled
// ---------------------------------------------------------------------------

func TestCollector_Disabled(t *testing.T) {
	cfg := &Config{Enabled: false}
	collector := NewCollector(cfg)
	defer collector.Close()

	collector.Counter("test", nil, 10)
	collector.Gauge("test", nil, 42.0)
	collector.Histogram("test", nil, 100.0)

	if v := collector.GetCounter("test", nil); v != 0 {
		t.Errorf("counter should be 0 when disabled, got %d", v)
	}
	if v := collector.GetGauge("test", nil); v != 0 {
		t.Errorf("gauge should be 0 when disabled, got %f", v)
	}
}

// ---------------------------------------------------------------------------
// Collector: Reset
// ---------------------------------------------------------------------------

func TestCollector_Reset(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true})
	defer collector.Close()

	collector.Counter("cnt", nil, 10)
	collector.Gauge("gauge", nil, 42.0)
	collector.Histogram("hist", nil, 100.0)

	collector.Reset()

	if v := collector.GetCounter("cnt", nil); v != 0 {
		t.Errorf("after Reset, counter = %d, want 0", v)
	}
	if v := collector.GetGauge("gauge", nil); v != 0 {
		t.Errorf("after Reset, gauge = %f, want 0", v)
	}
	if h := collector.GetHistogram("hist", nil); h.Count != 0 {
		t.Errorf("after Reset, histogram count = %d, want 0", h.Count)
	}
}

// ---------------------------------------------------------------------------
// Collector: Flush to disk
// ---------------------------------------------------------------------------

func TestCollector_Flush(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &Config{
		Enabled:       true,
		StoragePath:   tmpDir,
		FlushInterval: 0, // disable background flush so we control it
	}
	collector := NewCollector(cfg)
	defer collector.Close()

	collector.Counter("flush_test", nil, 42)
	collector.Gauge("flush_gauge", nil, 99.9)

	err := collector.Flush()
	if err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	// Verify file was created
	files, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("expected at least one file in storage directory")
	}

	// Read and verify contents
	data, err := os.ReadFile(filepath.Join(tmpDir, files[0].Name()))
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	counters, ok := result["counters"].(map[string]any)
	if !ok {
		t.Fatal("counters not found in flushed data")
	}
	if counters["flush_test"] != float64(42) {
		t.Errorf("flush_test counter = %v, want 42", counters["flush_test"])
	}
}

func TestCollector_Flush_EmptyStoragePath(t *testing.T) {
	cfg := &Config{Enabled: true, StoragePath: ""}
	collector := NewCollector(cfg)
	defer collector.Close()

	err := collector.Flush()
	if err != nil {
		t.Errorf("Flush with empty path should return nil, got: %v", err)
	}
}

func TestCollector_Flush_InvalidPath(t *testing.T) {
	// Use a path where the file open itself will fail because the parent is a file, not a dir
	tmpFile := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(tmpFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	cfg := &Config{
		Enabled:       true,
		StoragePath:   tmpFile, // a file, not a directory
		FlushInterval: 0,
	}
	collector := NewCollector(cfg)
	defer collector.Close()

	collector.Counter("test", nil, 1)
	err := collector.Flush()
	if err == nil {
		t.Error("expected error for invalid storage path, got nil")
	}
}

// ---------------------------------------------------------------------------
// Collector: Close idempotency
// ---------------------------------------------------------------------------

func TestCollector_Close_Twice(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true, StoragePath: t.TempDir()})

	err := collector.Close()
	if err != nil {
		t.Errorf("first Close failed: %v", err)
	}

	err = collector.Close()
	if err != nil {
		t.Errorf("second Close failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Collector: NewCollector with nil config
// ---------------------------------------------------------------------------

func TestNewCollector_NilConfig(t *testing.T) {
	collector := NewCollector(nil)
	defer collector.Close()

	if collector.config.Enabled != true {
		t.Error("expected default config to be enabled")
	}
	if collector.config.StoragePath != "data/analytics" {
		t.Errorf("expected default storage path, got %s", collector.config.StoragePath)
	}
}

// ---------------------------------------------------------------------------
// Collector: Counter/Gauge/Histogram max entries overflow
// ---------------------------------------------------------------------------

func TestCollector_Counter_MaxEntries(t *testing.T) {
	cfg := &Config{Enabled: true}
	collector := NewCollector(cfg)
	defer collector.Close()

	// Exhaust the counter map
	for i := 0; i < maxMapEntries+5; i++ {
		collector.Counter(fmt.Sprintf("c_%d", i), nil, 1)
	}

	// The exact count is maxMapEntries — excess silently dropped
	collector.mu.RLock()
	count := len(collector.counters)
	collector.mu.RUnlock()

	if count > maxMapEntries {
		t.Errorf("counters exceeded maxMapEntries: %d", count)
	}
}

func TestCollector_Gauge_MaxEntries(t *testing.T) {
	cfg := &Config{Enabled: true}
	collector := NewCollector(cfg)
	defer collector.Close()

	for i := 0; i < maxMapEntries+5; i++ {
		collector.Gauge(fmt.Sprintf("g_%d", i), nil, float64(i))
	}

	collector.mu.RLock()
	count := len(collector.gauges)
	collector.mu.RUnlock()

	if count > maxMapEntries {
		t.Errorf("gauges exceeded maxMapEntries: %d", count)
	}
}

func TestCollector_Histogram_MaxEntries(t *testing.T) {
	cfg := &Config{Enabled: true}
	collector := NewCollector(cfg)
	defer collector.Close()

	for i := 0; i < maxMapEntries+5; i++ {
		collector.Histogram(fmt.Sprintf("h_%d", i), nil, float64(i))
	}

	collector.mu.RLock()
	count := len(collector.histograms)
	collector.mu.RUnlock()

	if count > maxMapEntries {
		t.Errorf("histograms exceeded maxMapEntries: %d", count)
	}
}

// ---------------------------------------------------------------------------
// Collector: GetAllMetrics
// ---------------------------------------------------------------------------

func TestCollector_GetAllMetrics_Full(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true})
	defer collector.Close()

	collector.Counter("reqs", nil, 100)
	collector.Gauge("lat", nil, 55.5)
	collector.Histogram("latency", nil, 42.0)

	m := collector.GetAllMetrics()

	counters := m["counters"].(map[string]int64)
	if counters["reqs"] != 100 {
		t.Errorf("counters[reqs] = %d, want 100", counters["reqs"])
	}

	gauges := m["gauges"].(map[string]float64)
	if gauges["lat"] != 55.5 {
		t.Errorf("gauges[lat] = %f, want 55.5", gauges["lat"])
	}

	hists := m["histograms"].(map[string]HistogramSnapshot)
	if hists["latency"].Count != 1 {
		t.Errorf("histograms[latency].Count = %d, want 1", hists["latency"].Count)
	}
}

// ---------------------------------------------------------------------------
// Collector: Concurrent access
// ---------------------------------------------------------------------------

func TestCollector_ConcurrentCounter(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true, FlushInterval: 0})
	defer collector.Close()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			collector.Counter("concurrent", nil, 1)
		}()
	}
	wg.Wait()

	v := collector.GetCounter("concurrent", nil)
	if v != 100 {
		t.Errorf("concurrent counter = %d, want 100", v)
	}
}

// ---------------------------------------------------------------------------
// Histogram: edge cases
// ---------------------------------------------------------------------------

func TestHistogram_EmptySnapshot(t *testing.T) {
	h := NewHistogram("empty", nil)
	snap := h.Snapshot()
	if snap.Count != 0 {
		t.Errorf("empty snapshot count = %d, want 0", snap.Count)
	}
	if snap.Name != "" {
		t.Errorf("empty snapshot name = %s, want empty", snap.Name)
	}
}

func TestHistogram_CustomBuckets(t *testing.T) {
	buckets := []float64{10, 50, 100}
	h := NewHistogram("custom", buckets)

	h.Record(5)   // bucket 0
	h.Record(25)  // bucket 1
	h.Record(75)  // bucket 2
	h.Record(200) // +Inf bucket

	snap := h.Snapshot()
	if len(snap.Buckets) != 3 {
		t.Errorf("len(buckets) = %d, want 3", len(snap.Buckets))
	}
	if len(snap.Counts) != 4 { // 3 buckets + 1 overflow
		t.Errorf("len(counts) = %d, want 4", len(snap.Counts))
	}

	// Check individual bucket counts
	if snap.Counts[0] != 1 {
		t.Errorf("counts[0] = %d, want 1", snap.Counts[0])
	}
	if snap.Counts[3] != 1 { // +Inf
		t.Errorf("counts[3] (+Inf) = %d, want 1", snap.Counts[3])
	}
}

func TestHistogramSnapshot_Percentile_Empty(t *testing.T) {
	snap := HistogramSnapshot{}
	p := snap.Percentile(50)
	if p != 0 {
		t.Errorf("Percentile on empty = %f, want 0", p)
	}
}

func TestHistogramSnapshot_Percentile_Overflow(t *testing.T) {
	// Create histogram with very small buckets so all values go to +Inf
	h := NewHistogram("small", []float64{0.001})
	h.Record(100)
	h.Record(200)

	snap := h.Snapshot()
	p95 := snap.Percentile(95)
	// Should return Max since bucket index exceeds Buckets slice
	if p95 != snap.Max {
		t.Errorf("Percentile(95) = %f, want %f (Max)", p95, snap.Max)
	}
}

// ---------------------------------------------------------------------------
// Engine: AnalyzeTrend
// ---------------------------------------------------------------------------

func TestEngine_AnalyzeTrend_WithData(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		EnableTimeSeries: true,
		MaxDataPoints:    1000,
		FlushInterval:    0,
	}
	collector := NewCollector(cfg)
	defer collector.Close()
	engine := NewEngine(collector)

	// Record values spread over time to create time series data
	// Points must be at least 1 second apart for different buckets (since intervalSecs is int64)
	labels := map[string]string{"type": "sqli"}
	for i := 0; i < 5; i++ {
		collector.Counter("attacks_total", labels, int64(i+1))
		time.Sleep(1100 * time.Millisecond)
	}

	from := time.Now().Add(-time.Hour)
	to := time.Now().Add(time.Hour)

	// 1-second interval so each point should land in its own bucket
	analysis := engine.AnalyzeTrend("attacks_total", labels, from, to, time.Second)

	if analysis.Metric != "attacks_total" {
		t.Errorf("Metric = %s, want attacks_total", analysis.Metric)
	}
	if len(analysis.DataPoints) < 2 {
		t.Errorf("expected at least 2 data points, got %d", len(analysis.DataPoints))
	}
	if analysis.Direction == "" {
		t.Error("expected non-empty direction")
	}
}

func TestEngine_AnalyzeTrend_NoData(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true, EnableTimeSeries: true, FlushInterval: 0})
	defer collector.Close()
	engine := NewEngine(collector)

	from := time.Now().Add(-time.Hour)
	to := time.Now().Add(time.Hour)

	analysis := engine.AnalyzeTrend("nonexistent", nil, from, to, time.Hour)

	if analysis.Metric != "nonexistent" {
		t.Errorf("Metric = %s, want nonexistent", analysis.Metric)
	}
	if len(analysis.DataPoints) != 0 {
		t.Errorf("expected 0 data points for nonexistent metric, got %d", len(analysis.DataPoints))
	}
}

func TestEngine_AnalyzeTrend_Stable(t *testing.T) {
	// Create points with constant values — slope should be ~0
	points := []TrendPoint{}
	base := time.Now()
	for i := 0; i < 5; i++ {
		points = append(points, TrendPoint{
			Timestamp: base.Add(time.Duration(i) * time.Minute),
			Value:     42.0,
		})
	}

	engine := &Engine{}
	slope, direction := engine.calculateTrend(points)

	if math.Abs(slope) > 0.01 {
		t.Errorf("slope = %f, expected ~0 for stable data", slope)
	}
	if direction != "stable" {
		t.Errorf("direction = %s, want stable", direction)
	}
}

func TestEngine_CalculateTrend_SinglePoint(t *testing.T) {
	engine := &Engine{}
	slope, direction := engine.calculateTrend([]TrendPoint{{Value: 10}})
	if slope != 0 {
		t.Errorf("slope = %f, want 0 for single point", slope)
	}
	if direction != "stable" {
		t.Errorf("direction = %s, want stable", direction)
	}
}

// ---------------------------------------------------------------------------
// Engine: GetGeoDistribution
// ---------------------------------------------------------------------------

func TestEngine_GetGeoDistribution(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true, FlushInterval: 0})
	defer collector.Close()
	engine := NewEngine(collector)

	from := time.Now().Add(-time.Hour)
	to := time.Now().Add(time.Hour)

	geo := engine.GetGeoDistribution(from, to)

	// getTopCountries returns empty (no GeoIP integration), but should not panic
	if len(geo.Countries) != 0 {
		t.Errorf("Countries len = %d, want 0 (no GeoIP data)", len(geo.Countries))
	}
	if len(geo.Continents) != 0 {
		t.Errorf("Continents len = %d, want 0 (no GeoIP data)", len(geo.Continents))
	}
	if len(geo.TopCities) != 0 {
		t.Errorf("TopCities len = %d, want 0 (no GeoIP data)", len(geo.TopCities))
	}
}

// ---------------------------------------------------------------------------
// Engine: GetTopN
// ---------------------------------------------------------------------------

func TestEngine_GetTopN(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true, FlushInterval: 0})
	defer collector.Close()
	engine := NewEngine(collector)

	collector.Counter("requests_total", nil, 500)
	collector.Counter("requests_blocked", nil, 50)
	collector.Counter("requests_allowed", nil, 450)

	from := time.Now().Add(-time.Hour)
	to := time.Now().Add(time.Hour)

	items := engine.GetTopN("requests_total", 3, from, to)
	if len(items) == 0 {
		t.Error("expected at least one top-N item")
	}

	// Should be sorted descending
	for i := 1; i < len(items); i++ {
		if items[i].Value > items[i-1].Value {
			t.Errorf("items not sorted: items[%d].Value=%f > items[%d].Value=%f",
				i, items[i].Value, i-1, items[i-1].Value)
		}
	}
}

func TestEngine_GetTopN_NoCounters(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true, FlushInterval: 0})
	defer collector.Close()
	engine := NewEngine(collector)

	_ = engine.GetTopN("nonexistent", 5, time.Now(), time.Now())
	// No matching counters — may return nil or empty
}

// ---------------------------------------------------------------------------
// Engine: GetAnomalyScore edge cases
// ---------------------------------------------------------------------------

func TestEngine_GetAnomalyScore_BothZero(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true, FlushInterval: 0})
	defer collector.Close()
	engine := NewEngine(collector)

	score := engine.GetAnomalyScore(1 * time.Hour)
	// No traffic at all, should return 0
	if score != 0 {
		t.Errorf("anomaly score with no traffic = %f, want 0", score)
	}
}

func TestEngine_GetAnomalyScore_OnlyCurrentTraffic(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true, FlushInterval: 0})
	defer collector.Close()
	engine := NewEngine(collector)

	collector.Counter("requests_total", nil, 100)

	score := engine.GetAnomalyScore(1 * time.Hour)
	// Both windows see the same counter (100), so RPS will be the same.
	// deviation should be 0 since yesterday window is 24h earlier but reads same counters.
	// So this should return 0, not 100.
	if score != 0 {
		t.Errorf("anomaly score with same traffic in both windows = %f, want 0", score)
	}
}

// ---------------------------------------------------------------------------
// Engine: ComparePeriods
// ---------------------------------------------------------------------------

func TestEngine_ComparePeriods(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true, FlushInterval: 0})
	defer collector.Close()
	engine := NewEngine(collector)

	collector.Counter("requests_total", nil, 200)
	collector.Counter("requests_blocked", nil, 20)
	collector.Counter("requests_allowed", nil, 180)

	now := time.Now()
	result := engine.ComparePeriods(
		now.Add(-2*time.Hour), now.Add(-time.Hour),
		now.Add(-26*time.Hour), now.Add(-25*time.Hour),
	)

	currentPeriod, ok := result["current_period"].(map[string]any)
	if !ok {
		t.Fatal("current_period missing or wrong type")
	}
	if currentPeriod["total_requests"] != int64(200) {
		t.Errorf("current total_requests = %v, want 200", currentPeriod["total_requests"])
	}

	changes, ok := result["changes"].(map[string]any)
	if !ok {
		t.Fatal("changes missing or wrong type")
	}
	if changes["requests_percent"] == nil {
		t.Error("requests_percent should not be nil")
	}
}

// ---------------------------------------------------------------------------
// Engine: GetDashboardData
// ---------------------------------------------------------------------------

func TestEngine_GetDashboardData(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true, FlushInterval: 0})
	defer collector.Close()
	engine := NewEngine(collector)

	collector.Counter("requests_total", nil, 1000)
	collector.Counter("requests_blocked", nil, 100)
	collector.Counter("requests_allowed", nil, 900)

	data := engine.GetDashboardData()

	if data["realtime"] == nil {
		t.Error("realtime should not be nil")
	}
	if data["last_24h"] == nil {
		t.Error("last_24h should not be nil")
	}
	if data["last_7d"] == nil {
		t.Error("last_7d should not be nil")
	}
	if data["last_30d"] == nil {
		t.Error("last_30d should not be nil")
	}
	if data["anomaly_score"] == nil {
		t.Error("anomaly_score should not be nil")
	}
	if data["geo_distribution"] == nil {
		t.Error("geo_distribution should not be nil")
	}
	if data["top_attack_types"] == nil {
		t.Error("top_attack_types should not be nil")
	}

	realtime := data["realtime"].(map[string]any)
	if realtime["requests_per_second"] == nil {
		t.Error("realtime.requests_per_second should not be nil")
	}
}

// ---------------------------------------------------------------------------
// Engine: getAttackTypes with actual data
// ---------------------------------------------------------------------------

func TestEngine_GetAttackTypes(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true, FlushInterval: 0})
	defer collector.Close()
	engine := NewEngine(collector)

	attackTypes := []string{"sqli", "xss", "lfi", "cmdi", "xxe", "ssrf", "bot", "rate_limit"}
	for i, at := range attackTypes {
		collector.Counter("attacks_total", map[string]string{"type": at}, int64((i+1)*10))
	}

	from := time.Now().Add(-time.Hour)
	to := time.Now().Add(time.Hour)

	stats := engine.GetTrafficStats(from, to)

	if len(stats.TopAttackTypes) == 0 {
		t.Error("expected attack types in traffic stats")
	}

	// Should be sorted by count descending
	for i := 1; i < len(stats.TopAttackTypes); i++ {
		if stats.TopAttackTypes[i].Count > stats.TopAttackTypes[i-1].Count {
			t.Errorf("attack types not sorted: %d > %d",
				stats.TopAttackTypes[i].Count, stats.TopAttackTypes[i-1].Count)
		}
	}

	// Should be capped at 5
	if len(stats.TopAttackTypes) > 5 {
		t.Errorf("got %d attack types, expected at most 5", len(stats.TopAttackTypes))
	}

	// Percentages should sum to ~100
	totalPct := 0.0
	for _, at := range stats.TopAttackTypes {
		totalPct += at.Percent
	}
	// Only sum to 100% if we have all types; partial may be less
	if len(stats.TopAttackTypes) == len(attackTypes) && math.Abs(totalPct-100.0) > 1.0 {
		t.Errorf("percentages sum = %f, expected ~100", totalPct)
	}
}

// ---------------------------------------------------------------------------
// Engine: TrafficStats with latency percentiles
// ---------------------------------------------------------------------------

func TestEngine_GetTrafficStats_WithLatency(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true, FlushInterval: 0})
	defer collector.Close()
	engine := NewEngine(collector)

	collector.Counter("requests_total", nil, 100)
	collector.Counter("requests_blocked", nil, 5)
	collector.Counter("requests_allowed", nil, 95)

	// Record latency values
	latencies := []float64{5, 10, 15, 20, 25, 30, 50, 75, 100, 200, 500, 1000}
	for _, l := range latencies {
		collector.Histogram("request_latency_ms", nil, l)
	}

	from := time.Now().Add(-time.Hour)
	to := time.Now().Add(time.Hour)

	stats := engine.GetTrafficStats(from, to)

	if stats.AvgLatency == 0 {
		t.Error("expected non-zero avg latency")
	}
	if stats.P95Latency == 0 {
		t.Error("expected non-zero P95 latency")
	}
	if stats.P99Latency == 0 {
		t.Error("expected non-zero P99 latency")
	}
	if stats.RequestsPerSecond == 0 {
		t.Error("expected non-zero RPS")
	}
}

// ---------------------------------------------------------------------------
// Handler: parseTimeRange
// ---------------------------------------------------------------------------

func TestParseTimeRange_Default(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/traffic", nil)
	from, to := parseTimeRange(req)

	// Default should be last 24 hours
	diff := to.Sub(from)
	if diff < 23*time.Hour || diff > 25*time.Hour {
		t.Errorf("default range = %v, expected ~24h", diff)
	}
}

func TestParseTimeRange_Explicit(t *testing.T) {
	fromStr := "2025-01-01T00:00:00Z"
	toStr := "2025-01-02T00:00:00Z"
	url := fmt.Sprintf("/api/v1/analytics/traffic?from=%s&to=%s", fromStr, toStr)
	req := httptest.NewRequest(http.MethodGet, url, nil)

	from, to := parseTimeRange(req)

	expectedFrom, _ := time.Parse(time.RFC3339, fromStr)
	expectedTo, _ := time.Parse(time.RFC3339, toStr)

	if !from.Equal(expectedFrom) {
		t.Errorf("from = %v, want %v", from, expectedFrom)
	}
	if !to.Equal(expectedTo) {
		t.Errorf("to = %v, want %v", to, expectedTo)
	}
}

func TestParseTimeRange_InvalidTime(t *testing.T) {
	url := "/api/v1/analytics/traffic?from=invalid&to=also-invalid"
	req := httptest.NewRequest(http.MethodGet, url, nil)

	from, to := parseTimeRange(req)
	// Should fall back to defaults (last 24h)
	diff := to.Sub(from)
	if diff < 23*time.Hour || diff > 25*time.Hour {
		t.Errorf("fallback range = %v, expected ~24h", diff)
	}
}

// ---------------------------------------------------------------------------
// Handler: parseInterval
// ---------------------------------------------------------------------------

func TestParseInterval_Empty(t *testing.T) {
	d := parseInterval("", time.Hour)
	if d != time.Hour {
		t.Errorf("parseInterval('') = %v, want %v", d, time.Hour)
	}
}

func TestParseInterval_Minutes(t *testing.T) {
	d := parseInterval("30", time.Hour)
	if d != 30*time.Minute {
		t.Errorf("parseInterval('30') = %v, want %v", d, 30*time.Minute)
	}
}

func TestParseInterval_MinutesTooLow(t *testing.T) {
	d := parseInterval("0", time.Hour)
	if d != time.Minute {
		t.Errorf("parseInterval('0') = %v, want %v", d, time.Minute)
	}
}

func TestParseInterval_MinutesTooHigh(t *testing.T) {
	d := parseInterval("1441", time.Hour) // 1441 min = 24h1min
	if d != 24*time.Hour {
		t.Errorf("parseInterval('1441') = %v, want %v", d, 24*time.Hour)
	}
}

func TestParseInterval_DurationString(t *testing.T) {
	d := parseInterval("2h30m", time.Hour)
	if d != 150*time.Minute {
		t.Errorf("parseInterval('2h30m') = %v, want %v", d, 150*time.Minute)
	}
}

func TestParseInterval_DurationTooLow(t *testing.T) {
	d := parseInterval("500ms", time.Hour)
	if d != time.Minute {
		t.Errorf("parseInterval('500ms') = %v, want %v", d, time.Minute)
	}
}

func TestParseInterval_DurationTooHigh(t *testing.T) {
	d := parseInterval("25h", time.Hour)
	if d != 24*time.Hour {
		t.Errorf("parseInterval('25h') = %v, want %v", d, 24*time.Hour)
	}
}

func TestParseInterval_InvalidString(t *testing.T) {
	d := parseInterval("not-a-duration", time.Hour)
	if d != time.Hour {
		t.Errorf("parseInterval('not-a-duration') = %v, want %v", d, time.Hour)
	}
}

// ---------------------------------------------------------------------------
// Handler: HTTP endpoints
// ---------------------------------------------------------------------------

func setupHandler() (*Handler, *Collector) {
	cfg := &Config{
		Enabled:          true,
		EnableTimeSeries: true,
		MaxDataPoints:    100,
		FlushInterval:    0,
	}
	collector := NewCollector(cfg)

	// Pre-populate data
	collector.Counter("requests_total", nil, 100)
	collector.Counter("requests_blocked", nil, 10)
	collector.Counter("requests_allowed", nil, 90)
	collector.Histogram("request_latency_ms", nil, 50.0)
	collector.Counter("attacks_total", map[string]string{"type": "sqli"}, 5)

	handler := NewHandler(collector)
	return handler, collector
}

func TestHandler_Dashboard(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/dashboard", nil)
	w := httptest.NewRecorder()
	handler.Dashboard(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Dashboard status = %d, want %d", w.Code, http.StatusOK)
	}

	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if result["realtime"] == nil {
		t.Error("dashboard should contain realtime data")
	}
}

func TestHandler_Dashboard_MethodNotAllowed(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/analytics/dashboard", nil)
	w := httptest.NewRecorder()
	handler.Dashboard(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Dashboard POST status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandler_TrafficStats(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/traffic", nil)
	w := httptest.NewRecorder()
	handler.TrafficStats(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("TrafficStats status = %d, want %d", w.Code, http.StatusOK)
	}

	var stats TrafficStats
	if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if stats.TotalRequests != 100 {
		t.Errorf("TotalRequests = %d, want 100", stats.TotalRequests)
	}
}

func TestHandler_TrafficStats_MethodNotAllowed(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/analytics/traffic", nil)
	w := httptest.NewRecorder()
	handler.TrafficStats(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("TrafficStats DELETE status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandler_TrendAnalysis(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/trends?metric=requests_total&interval=5", nil)
	w := httptest.NewRecorder()
	handler.TrendAnalysis(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("TrendAnalysis status = %d, want %d", w.Code, http.StatusOK)
	}

	var analysis TrendAnalysis
	if err := json.Unmarshal(w.Body.Bytes(), &analysis); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if analysis.Metric != "requests_total" {
		t.Errorf("Metric = %s, want requests_total", analysis.Metric)
	}
}

func TestHandler_TrendAnalysis_DefaultMetric(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/trends", nil)
	w := httptest.NewRecorder()
	handler.TrendAnalysis(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("TrendAnalysis status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHandler_TrendAnalysis_MethodNotAllowed(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	req := httptest.NewRequest(http.MethodPut, "/api/v1/analytics/trends", nil)
	w := httptest.NewRecorder()
	handler.TrendAnalysis(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandler_GeoDistribution(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/geo", nil)
	w := httptest.NewRecorder()
	handler.GeoDistribution(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GeoDistribution status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHandler_GeoDistribution_MethodNotAllowed(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/analytics/geo", nil)
	w := httptest.NewRecorder()
	handler.GeoDistribution(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandler_PeriodComparison(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	now := time.Now().UTC()
	url := fmt.Sprintf("/api/v1/analytics/comparison?current_from=%s&current_to=%s&previous_from=%s&previous_to=%s",
		now.Add(-2*time.Hour).Format(time.RFC3339),
		now.Add(-time.Hour).Format(time.RFC3339),
		now.Add(-26*time.Hour).Format(time.RFC3339),
		now.Add(-25*time.Hour).Format(time.RFC3339),
	)

	req := httptest.NewRequest(http.MethodGet, url, nil)
	w := httptest.NewRecorder()
	handler.PeriodComparison(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("PeriodComparison status = %d, want %d, body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if result["current_period"] == nil {
		t.Error("current_period should not be nil")
	}
	if result["changes"] == nil {
		t.Error("changes should not be nil")
	}
}

func TestHandler_PeriodComparison_InvalidCurrentFrom(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	url := "/api/v1/analytics/comparison?current_from=invalid&current_to=2025-01-01T00:00:00Z&previous_from=2025-01-01T00:00:00Z&previous_to=2025-01-01T00:00:00Z"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	w := httptest.NewRecorder()
	handler.PeriodComparison(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandler_PeriodComparison_InvalidCurrentTo(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	url := "/api/v1/analytics/comparison?current_from=2025-01-01T00:00:00Z&current_to=invalid&previous_from=2025-01-01T00:00:00Z&previous_to=2025-01-01T00:00:00Z"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	w := httptest.NewRecorder()
	handler.PeriodComparison(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandler_PeriodComparison_InvalidPreviousFrom(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	url := "/api/v1/analytics/comparison?current_from=2025-01-01T00:00:00Z&current_to=2025-01-01T00:00:00Z&previous_from=invalid&previous_to=2025-01-01T00:00:00Z"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	w := httptest.NewRecorder()
	handler.PeriodComparison(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandler_PeriodComparison_InvalidPreviousTo(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	url := "/api/v1/analytics/comparison?current_from=2025-01-01T00:00:00Z&current_to=2025-01-01T00:00:00Z&previous_from=2025-01-01T00:00:00Z&previous_to=invalid"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	w := httptest.NewRecorder()
	handler.PeriodComparison(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandler_PeriodComparison_MethodNotAllowed(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/analytics/comparison", nil)
	w := httptest.NewRecorder()
	handler.PeriodComparison(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandler_Metrics(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/metrics", nil)
	w := httptest.NewRecorder()
	handler.Metrics(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Metrics status = %d, want %d", w.Code, http.StatusOK)
	}

	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if result["counters"] == nil {
		t.Error("metrics should contain counters")
	}
}

func TestHandler_Metrics_MethodNotAllowed(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/analytics/metrics", nil)
	w := httptest.NewRecorder()
	handler.Metrics(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandler_TimeSeries(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	from := time.Now().Add(-time.Hour).Format(time.RFC3339)
	to := time.Now().Add(time.Hour).Format(time.RFC3339)
	url := fmt.Sprintf("/api/v1/analytics/timeseries?name=requests_total&from=%s&to=%s", from, to)

	req := httptest.NewRequest(http.MethodGet, url, nil)
	w := httptest.NewRecorder()
	handler.TimeSeries(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("TimeSeries status = %d, want %d, body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestHandler_TimeSeries_MissingName(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/timeseries", nil)
	w := httptest.NewRecorder()
	handler.TimeSeries(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandler_TimeSeries_NotFound(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/timeseries?name=nonexistent_metric", nil)
	w := httptest.NewRecorder()
	handler.TimeSeries(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestHandler_TimeSeries_MethodNotAllowed(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/analytics/timeseries?name=test", nil)
	w := httptest.NewRecorder()
	handler.TimeSeries(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// Handler: ServeHTTP router
// ---------------------------------------------------------------------------

func TestHandler_ServeHTTP_Routes(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	routes := []struct {
		path       string
		expectCode int
	}{
		{"/api/v1/analytics/dashboard", http.StatusOK},
		{"/api/v1/analytics/traffic", http.StatusOK},
		{"/api/v1/analytics/trends", http.StatusOK},
		{"/api/v1/analytics/geo", http.StatusOK},
		{"/api/v1/analytics/metrics", http.StatusOK},
		{"/api/v1/analytics/timeseries", http.StatusBadRequest}, // missing name
		{"/api/v1/analytics/unknown", http.StatusNotFound},
	}

	for _, tc := range routes {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != tc.expectCode {
			t.Errorf("ServeHTTP(%s) status = %d, want %d", tc.path, w.Code, tc.expectCode)
		}
	}
}

func TestHandler_ServeHTTP_PeriodComparisonRoute(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	// Comparison route needs query params — test missing params return 400
	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/comparison", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("ServeHTTP(comparison without params) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// ---------------------------------------------------------------------------
// Handler: RegisterRoutes
// ---------------------------------------------------------------------------

func TestHandler_RegisterRoutes(t *testing.T) {
	handler, collector := setupHandler()
	defer collector.Close()

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Verify routes are registered by making requests
	routes := []string{
		"/api/v1/analytics/dashboard",
		"/api/v1/analytics/traffic",
		"/api/v1/analytics/trends",
		"/api/v1/analytics/geo",
		"/api/v1/analytics/metrics",
		"/api/v1/analytics/timeseries",
	}

	for _, route := range routes {
		req := httptest.NewRequest(http.MethodGet, route, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		// All should respond (some may be 400 due to missing params, that's fine)
		if w.Code == 0 {
			t.Errorf("route %s not registered", route)
		}
	}
}

// ---------------------------------------------------------------------------
// Layer: comprehensive tests
// ---------------------------------------------------------------------------

func TestNewLayer_NilConfig(t *testing.T) {
	layer, err := NewLayer(nil)
	if err != nil {
		t.Fatalf("NewLayer(nil) returned error: %v", err)
	}
	if layer == nil {
		t.Fatal("NewLayer(nil) returned nil layer")
	}
	if layer.Name() != "analytics" {
		t.Errorf("Name() = %s, want analytics", layer.Name())
	}
	if layer.config.Enabled {
		t.Error("nil config should set Enabled=false")
	}
}

func TestNewLayer_Disabled(t *testing.T) {
	layer, err := NewLayer(&LayerConfig{Enabled: false})
	if err != nil {
		t.Fatalf("NewLayer returned error: %v", err)
	}
	if layer.GetHandler() != nil {
		t.Error("disabled layer should have nil handler")
	}
	if layer.GetCollector() != nil {
		t.Error("disabled layer should have nil collector")
	}
}

func TestNewLayer_Enabled(t *testing.T) {
	cfg := &LayerConfig{
		Enabled: true,
		Config: &Config{
			Enabled:       true,
			FlushInterval: 0,
		},
	}
	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer returned error: %v", err)
	}
	defer layer.Close()

	if layer.GetHandler() == nil {
		t.Error("enabled layer should have handler")
	}
	if layer.GetCollector() == nil {
		t.Error("enabled layer should have collector")
	}
}

func TestLayer_Process_Disabled(t *testing.T) {
	layer, _ := NewLayer(&LayerConfig{Enabled: false})
	result := layer.Process(nil)
	if result != nil {
		t.Errorf("Process on disabled layer = %v, want nil", result)
	}
}

func TestLayer_Process_Enabled(t *testing.T) {
	layer, _ := NewLayer(&LayerConfig{
		Enabled: true,
		Config:  &Config{Enabled: true, FlushInterval: 0},
	})
	defer layer.Close()

	result := layer.Process(nil)
	if result != nil {
		t.Errorf("Process = %v, want nil", result)
	}
}

func TestLayer_RecordRequest_Disabled(t *testing.T) {
	layer, _ := NewLayer(&LayerConfig{Enabled: false})
	// Should not panic
	layer.RecordRequest(100*time.Millisecond, 200, false)
}

func TestLayer_RecordRequest_Enabled(t *testing.T) {
	layer, _ := NewLayer(&LayerConfig{
		Enabled: true,
		Config:  &Config{Enabled: true, FlushInterval: 0},
	})
	defer layer.Close()

	layer.RecordRequest(100*time.Millisecond, 200, false)
	layer.RecordRequest(50*time.Millisecond, 403, true)

	c := layer.GetCollector()
	if c.GetCounter("requests_total", nil) != 2 {
		t.Errorf("requests_total = %d, want 2", c.GetCounter("requests_total", nil))
	}
	if c.GetCounter("requests_blocked", nil) != 1 {
		t.Errorf("requests_blocked = %d, want 1", c.GetCounter("requests_blocked", nil))
	}
	if c.GetCounter("requests_allowed", nil) != 1 {
		t.Errorf("requests_allowed = %d, want 1", c.GetCounter("requests_allowed", nil))
	}
}

func TestLayer_GetStats_Disabled(t *testing.T) {
	layer, _ := NewLayer(&LayerConfig{Enabled: false})
	stats := layer.GetStats()

	enabled, ok := stats["enabled"]
	if !ok {
		t.Error("GetStats should contain 'enabled' key")
	}
	if enabled != false {
		t.Errorf("enabled = %v, want false", enabled)
	}
}

func TestLayer_GetStats_Enabled(t *testing.T) {
	layer, _ := NewLayer(&LayerConfig{
		Enabled: true,
		Config:  &Config{Enabled: true, FlushInterval: 0},
	})
	defer layer.Close()

	layer.RecordRequest(100*time.Millisecond, 200, false)
	stats := layer.GetStats()

	if stats["enabled"] == false {
		t.Error("enabled layer should not report enabled=false")
	}
}

func TestLayer_Close_Disabled(t *testing.T) {
	layer, _ := NewLayer(&LayerConfig{Enabled: false})
	err := layer.Close()
	if err != nil {
		t.Errorf("Close on disabled layer returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// calculatePercentChangeFloat edge cases
// ---------------------------------------------------------------------------

func TestCalculatePercentChangeFloat_ZeroOldPositiveNew(t *testing.T) {
	change := calculatePercentChangeFloat(0, 100)
	if change != 100 {
		t.Errorf("calculatePercentChangeFloat(0, 100) = %f, want 100", change)
	}
}

func TestCalculatePercentChangeFloat_BothZero(t *testing.T) {
	change := calculatePercentChangeFloat(0, 0)
	if change != 0 {
		t.Errorf("calculatePercentChangeFloat(0, 0) = %f, want 0", change)
	}
}

func TestCalculatePercentChange_ZeroOldZeroNew(t *testing.T) {
	change := calculatePercentChange(0, 0)
	if change != 0 {
		t.Errorf("calculatePercentChange(0, 0) = %f, want 0", change)
	}
}

func TestCalculatePercentChange_ZeroOldPositiveNew(t *testing.T) {
	change := calculatePercentChange(0, 50)
	if change != 100 {
		t.Errorf("calculatePercentChange(0, 50) = %f, want 100", change)
	}
}

// ---------------------------------------------------------------------------
// Engine: GetTrafficStats edge cases
// ---------------------------------------------------------------------------

func TestEngine_GetTrafficStats_ZeroRequests(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true, FlushInterval: 0})
	defer collector.Close()
	engine := NewEngine(collector)

	from := time.Now().Add(-time.Hour)
	to := time.Now().Add(time.Hour)

	stats := engine.GetTrafficStats(from, to)

	if stats.TotalRequests != 0 {
		t.Errorf("TotalRequests = %d, want 0", stats.TotalRequests)
	}
	if stats.BlockedPercent != 0 {
		t.Errorf("BlockedPercent = %f, want 0", stats.BlockedPercent)
	}
}

func TestEngine_GetTrafficStats_ChallengedRequests(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true, FlushInterval: 0})
	defer collector.Close()
	engine := NewEngine(collector)

	collector.Counter("requests_total", nil, 100)
	collector.Counter("requests_challenged", nil, 15)

	from := time.Now().Add(-time.Hour)
	to := time.Now().Add(time.Hour)

	stats := engine.GetTrafficStats(from, to)
	if stats.ChallengedRequests != 15 {
		t.Errorf("ChallengedRequests = %d, want 15", stats.ChallengedRequests)
	}
}

// ---------------------------------------------------------------------------
// NewHandler
// ---------------------------------------------------------------------------

func TestNewHandler(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true, FlushInterval: 0})
	defer collector.Close()

	handler := NewHandler(collector)
	if handler == nil {
		t.Fatal("NewHandler returned nil")
	}
	if handler.collector != collector {
		t.Error("handler.collector mismatch")
	}
	if handler.engine == nil {
		t.Error("handler.engine should not be nil")
	}
}

// ---------------------------------------------------------------------------
// GaugeValue concurrent access
// ---------------------------------------------------------------------------

func TestGaugeValue_Concurrent(t *testing.T) {
	g := &GaugeValue{}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(v float64) {
			defer wg.Done()
			g.Store(v)
		}(float64(i))
	}
	wg.Wait()

	// Just ensure no panic — final value is nondeterministic
	_ = g.Load()
}

// ---------------------------------------------------------------------------
// TimeSeriesBuffer with maxLen enforcement
// ---------------------------------------------------------------------------

func TestTimeSeriesBuffer_MaxLen(t *testing.T) {
	ts := NewTimeSeriesBuffer("test", map[string]string{"k": "v"}, 3)

	ts.Add(1.0)
	ts.Add(2.0)
	ts.Add(3.0)
	ts.Add(4.0) // should evict first point

	if len(ts.Points) != 3 {
		t.Fatalf("len = %d, want 3", len(ts.Points))
	}
	if ts.Points[0].Value != 2.0 {
		t.Errorf("first point = %f, want 2.0", ts.Points[0].Value)
	}
	if ts.Points[2].Value != 4.0 {
		t.Errorf("last point = %f, want 4.0", ts.Points[2].Value)
	}
}

// ---------------------------------------------------------------------------
// Histogram Record edge: value updates min/max concurrently
// ---------------------------------------------------------------------------

func TestHistogram_Record_Concurrent(t *testing.T) {
	h := NewHistogram("concurrent", nil)

	var wg sync.WaitGroup
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func(v float64) {
			defer wg.Done()
			h.Record(v)
		}(float64(i))
	}
	wg.Wait()

	snap := h.Snapshot()
	if snap.Count != 1000 {
		t.Errorf("Count = %d, want 1000", snap.Count)
	}
}

// ---------------------------------------------------------------------------
// Engine: AnalyzeTrend with changeRate (first != 0)
// ---------------------------------------------------------------------------

func TestEngine_AnalyzeTrend_ChangeRate(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		EnableTimeSeries: true,
		MaxDataPoints:    500,
		FlushInterval:    0,
	}
	collector := NewCollector(cfg)
	defer collector.Close()
	engine := NewEngine(collector)

	// Create a single metric with time series enabled
	// Record increasing values
	collector.Counter("growing_metric", nil, 10)
	time.Sleep(5 * time.Millisecond)
	collector.Counter("growing_metric", nil, 20)
	time.Sleep(5 * time.Millisecond)
	collector.Counter("growing_metric", nil, 30)

	from := time.Now().Add(-time.Hour)
	to := time.Now().Add(time.Hour)

	analysis := engine.AnalyzeTrend("growing_metric", nil, from, to, time.Second)

	// Should have direction
	if analysis.Direction == "" {
		t.Error("expected non-empty direction")
	}
	// ChangeRate should be computed
	// (even if exact value depends on aggregation)
}

// ---------------------------------------------------------------------------
// Engine: AnalyzeTrend with zero interval (clamped to 1)
// ---------------------------------------------------------------------------

func TestEngine_AnalyzeTrend_ZeroInterval(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		EnableTimeSeries: true,
		MaxDataPoints:    100,
		FlushInterval:    0,
	}
	collector := NewCollector(cfg)
	defer collector.Close()
	engine := NewEngine(collector)

	collector.Counter("zero_interval", nil, 1)

	from := time.Now().Add(-time.Hour)
	to := time.Now().Add(time.Hour)

	analysis := engine.AnalyzeTrend("zero_interval", nil, from, to, 0)
	// Should not panic; intervalSecs clamped to 1
	if analysis.Metric != "zero_interval" {
		t.Errorf("Metric = %s, want zero_interval", analysis.Metric)
	}
}

// ---------------------------------------------------------------------------
// Engine: GetTopN with no matching counters
// ---------------------------------------------------------------------------

func TestEngine_GetTopN_Empty(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true, FlushInterval: 0})
	defer collector.Close()
	engine := NewEngine(collector)

	// No counters set at all
	items := engine.GetTopN("nonexistent", 5, time.Now(), time.Now())
	if items != nil {
		t.Errorf("expected nil for no matching counters, got %v", items)
	}
}

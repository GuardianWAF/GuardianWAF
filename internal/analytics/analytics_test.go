package analytics

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.Enabled {
		t.Error("expected analytics to be enabled by default")
	}

	if cfg.StoragePath != "data/analytics" {
		t.Errorf("storage_path = %s, want data/analytics", cfg.StoragePath)
	}

	if cfg.RetentionDays != 30 {
		t.Errorf("retention_days = %d, want 30", cfg.RetentionDays)
	}

	if cfg.MaxDataPoints != 10000 {
		t.Errorf("max_data_points = %d, want 10000", cfg.MaxDataPoints)
	}
}

func TestNewCollector(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &Config{
		Enabled:       true,
		StoragePath:   tmpDir,
		FlushInterval: time.Hour,
	}

	collector := NewCollector(cfg)
	defer collector.Close()

	if collector == nil {
		t.Fatal("expected collector, got nil")
	}

	if collector.config != cfg {
		t.Error("config mismatch")
	}
}

func TestCollector_Counter(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true})
	defer collector.Close()

	// Increment counter
	collector.Counter("test_counter", nil, 5)
	collector.Counter("test_counter", nil, 3)

	// Check value
	value := collector.GetCounter("test_counter", nil)
	if value != 8 {
		t.Errorf("counter = %d, want 8", value)
	}
}

func TestCollector_Gauge(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true})
	defer collector.Close()

	// Set gauge
	collector.Gauge("test_gauge", nil, 42.5)

	// Check value
	value := collector.GetGauge("test_gauge", nil)
	if value != 42.5 {
		t.Errorf("gauge = %f, want 42.5", value)
	}

	// Update gauge
	collector.Gauge("test_gauge", nil, 100.0)

	value = collector.GetGauge("test_gauge", nil)
	if value != 100.0 {
		t.Errorf("gauge = %f, want 100.0", value)
	}
}

func TestCollector_Histogram(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true})
	defer collector.Close()

	// Record values
	values := []float64{10, 20, 30, 40, 50, 100, 200, 500, 1000}
	for _, v := range values {
		collector.Histogram("test_histogram", nil, v)
	}

	// Get histogram
	hist := collector.GetHistogram("test_histogram", nil)

	if hist.Count != int64(len(values)) {
		t.Errorf("count = %d, want %d", hist.Count, len(values))
	}

	if hist.Min != 10 {
		t.Errorf("min = %f, want 10", hist.Min)
	}

	if hist.Max != 1000 {
		t.Errorf("max = %f, want 1000", hist.Max)
	}
}

func TestHistogram_Percentile(t *testing.T) {
	hist := NewHistogram("test", nil)

	// Record values 1-100
	for i := 1; i <= 100; i++ {
		hist.Record(float64(i))
	}

	snapshot := hist.Snapshot()

	// Check percentiles
	p50 := snapshot.Percentile(50)
	if p50 < 45 || p50 > 55 {
		t.Errorf("p50 = %f, expected around 50", p50)
	}

	p95 := snapshot.Percentile(95)
	if p95 < 90 || p95 > 100 {
		t.Errorf("p95 = %f, expected around 95", p95)
	}
}

func TestTimeSeriesBuffer(t *testing.T) {
	ts := NewTimeSeriesBuffer("test", nil, 10)

	// Add points
	for i := 0; i < 15; i++ {
		ts.Add(float64(i))
		time.Sleep(1 * time.Millisecond)
	}

	// Should only keep last 10
	if len(ts.Points) != 10 {
		t.Errorf("points = %d, want 10", len(ts.Points))
	}

	// Check values (should be 5-14)
	if ts.Points[0].Value != 5 {
		t.Errorf("first point = %f, want 5", ts.Points[0].Value)
	}
	if ts.Points[9].Value != 14 {
		t.Errorf("last point = %f, want 14", ts.Points[9].Value)
	}
}

func TestMetricKey(t *testing.T) {
	// No labels
	key := metricKey("test_metric", nil)
	if key != "test_metric" {
		t.Errorf("key = %s, want test_metric", key)
	}

	// With labels
	labels := map[string]string{
		"host":  "example.com",
		"path":  "/api",
		"method": "GET",
	}
	key = metricKey("test_metric", labels)

	// Should be sorted
	expected := "test_metric;host=example.com;method=GET;path=/api"
	if key != expected {
		t.Errorf("key = %s, want %s", key, expected)
	}
}

func TestNewEngine(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true})
	defer collector.Close()

	engine := NewEngine(collector)

	if engine == nil {
		t.Fatal("expected engine, got nil")
	}

	if engine.collector != collector {
		t.Error("collector mismatch")
	}
}

func TestEngine_GetTrafficStats(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true})
	defer collector.Close()

	engine := NewEngine(collector)

	// Record some metrics
	collector.Counter("requests_total", nil, 100)
	collector.Counter("requests_blocked", nil, 10)
	collector.Counter("requests_allowed", nil, 90)

	for i := 0; i < 10; i++ {
		collector.Histogram("request_latency_ms", nil, float64(i*10))
	}

	from := time.Now().Add(-time.Hour)
	to := time.Now()

	stats := engine.GetTrafficStats(from, to)

	if stats.TotalRequests != 100 {
		t.Errorf("total_requests = %d, want 100", stats.TotalRequests)
	}

	if stats.BlockedRequests != 10 {
		t.Errorf("blocked_requests = %d, want 10", stats.BlockedRequests)
	}

	if stats.BlockedPercent != 10.0 {
		t.Errorf("blocked_percent = %f, want 10.0", stats.BlockedPercent)
	}
}

func TestCalculateTrend(t *testing.T) {
	engine := &Engine{}

	// Increasing trend
	points := []TrendPoint{
		{Value: 10},
		{Value: 20},
		{Value: 30},
		{Value: 40},
		{Value: 50},
	}

	slope, direction := engine.calculateTrend(points)

	if slope <= 0 {
		t.Error("expected positive slope for increasing trend")
	}

	if direction != "increasing" {
		t.Errorf("direction = %s, want increasing", direction)
	}

	// Decreasing trend
	points = []TrendPoint{
		{Value: 50},
		{Value: 40},
		{Value: 30},
		{Value: 20},
		{Value: 10},
	}

	slope, direction = engine.calculateTrend(points)

	if slope >= 0 {
		t.Error("expected negative slope for decreasing trend")
	}

	if direction != "decreasing" {
		t.Errorf("direction = %s, want decreasing", direction)
	}
}

func TestCalculatePercentChange(t *testing.T) {
	// Normal case
	change := calculatePercentChange(100, 150)
	if change != 50 {
		t.Errorf("percent_change = %f, want 50", change)
	}

	// Decrease
	change = calculatePercentChange(100, 50)
	if change != -50 {
		t.Errorf("percent_change = %f, want -50", change)
	}

	// Zero old value
	change = calculatePercentChange(0, 100)
	if change != 100 {
		t.Errorf("percent_change = %f, want 100", change)
	}
}

func TestCalculatePercentChangeFloat(t *testing.T) {
	// Normal case
	change := calculatePercentChangeFloat(100.0, 150.0)
	if change != 50.0 {
		t.Errorf("percent_change = %f, want 50", change)
	}

	// Decrease
	change = calculatePercentChangeFloat(100.0, 50.0)
	if change != -50.0 {
		t.Errorf("percent_change = %f, want -50", change)
	}
}

func TestLayer_Name(t *testing.T) {
	layer, _ := NewLayer(&LayerConfig{Enabled: false})

	if layer.Name() != "analytics" {
		t.Errorf("Name() = %s, want analytics", layer.Name())
	}
}

func TestLayer_Order(t *testing.T) {
	layer, _ := NewLayer(&LayerConfig{Enabled: false})

	if layer.Order() != 50 {
		t.Errorf("Order() = %d, want 50", layer.Order())
	}
}

func TestEngine_GetAnomalyScore(t *testing.T) {
	collector := NewCollector(&Config{Enabled: true})
	defer collector.Close()

	engine := NewEngine(collector)

	// Record some traffic
	collector.Counter("requests_total", nil, 100)

	score := engine.GetAnomalyScore(1 * time.Hour)

	// Score should be between 0 and 100
	if score < 0 || score > 100 {
		t.Errorf("anomaly_score = %f, should be 0-100", score)
	}
}

func TestEngine_countryToContinent(t *testing.T) {
	engine := &Engine{}

	tests := []struct {
		code      string
		continent string
	}{
		{"US", "North America"},
		{"DE", "Europe"},
		{"JP", "Asia"},
		{"BR", "South America"},
		{"ZA", "Africa"},
		{"AU", "Oceania"},
		{"XX", "Unknown"},
	}

	for _, tt := range tests {
		result := engine.countryToContinent(tt.code)
		if result != tt.continent {
			t.Errorf("countryToContinent(%s) = %s, want %s", tt.code, result, tt.continent)
		}
	}
}

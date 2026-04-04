package analytics

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// Handler provides HTTP handlers for analytics API.
type Handler struct {
	collector *Collector
	engine    *Engine
}

// NewHandler creates a new analytics handler.
func NewHandler(collector *Collector) *Handler {
	return &Handler{
		collector: collector,
		engine:    NewEngine(collector),
	}
}

// RegisterRoutes registers analytics API routes.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/analytics/dashboard", h.Dashboard)
	mux.HandleFunc("/api/v1/analytics/traffic", h.TrafficStats)
	mux.HandleFunc("/api/v1/analytics/trends", h.TrendAnalysis)
	mux.HandleFunc("/api/v1/analytics/geo", h.GeoDistribution)
	mux.HandleFunc("/api/v1/analytics/comparison", h.PeriodComparison)
	mux.HandleFunc("/api/v1/analytics/metrics", h.Metrics)
	mux.HandleFunc("/api/v1/analytics/timeseries", h.TimeSeries)
}

// ServeHTTP implements http.Handler interface.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Route to appropriate handler based on path
	switch r.URL.Path {
	case "/api/v1/analytics/dashboard":
		h.Dashboard(w, r)
	case "/api/v1/analytics/traffic":
		h.TrafficStats(w, r)
	case "/api/v1/analytics/trends":
		h.TrendAnalysis(w, r)
	case "/api/v1/analytics/geo":
		h.GeoDistribution(w, r)
	case "/api/v1/analytics/comparison":
		h.PeriodComparison(w, r)
	case "/api/v1/analytics/metrics":
		h.Metrics(w, r)
	case "/api/v1/analytics/timeseries":
		h.TimeSeries(w, r)
	default:
		http.NotFound(w, r)
	}
}

// Dashboard returns dashboard data.
func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	data := h.engine.GetDashboardData()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// TrafficStats returns traffic statistics.
func (h *Handler) TrafficStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	from, to := parseTimeRange(r)
	stats := h.engine.GetTrafficStats(from, to)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// TrendAnalysis returns trend analysis.
func (h *Handler) TrendAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metric := r.URL.Query().Get("metric")
	if metric == "" {
		metric = "requests_total"
	}

	from, to := parseTimeRange(r)
	interval := parseInterval(r.URL.Query().Get("interval"), time.Hour)

	analysis := h.engine.AnalyzeTrend(metric, nil, from, to, interval)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(analysis)
}

// GeoDistribution returns geographic distribution.
func (h *Handler) GeoDistribution(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	from, to := parseTimeRange(r)
	geo := h.engine.GetGeoDistribution(from, to)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(geo)
}

// PeriodComparison compares two time periods.
func (h *Handler) PeriodComparison(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse current period
	currentFrom, err := time.Parse(time.RFC3339, r.URL.Query().Get("current_from"))
	if err != nil {
		http.Error(w, "Invalid current_from", http.StatusBadRequest)
		return
	}
	currentTo, err := time.Parse(time.RFC3339, r.URL.Query().Get("current_to"))
	if err != nil {
		http.Error(w, "Invalid current_to", http.StatusBadRequest)
		return
	}

	// Parse previous period
	previousFrom, err := time.Parse(time.RFC3339, r.URL.Query().Get("previous_from"))
	if err != nil {
		http.Error(w, "Invalid previous_from", http.StatusBadRequest)
		return
	}
	previousTo, err := time.Parse(time.RFC3339, r.URL.Query().Get("previous_to"))
	if err != nil {
		http.Error(w, "Invalid previous_to", http.StatusBadRequest)
		return
	}

	comparison := h.engine.ComparePeriods(currentFrom, currentTo, previousFrom, previousTo)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(comparison)
}

// Metrics returns all current metrics.
func (h *Handler) Metrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metrics := h.collector.GetAllMetrics()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// TimeSeries returns time series data for a metric.
func (h *Handler) TimeSeries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "name parameter required", http.StatusBadRequest)
		return
	}

	from, to := parseTimeRange(r)

	ts := h.collector.GetTimeSeries(name, nil, from, to)
	if ts == nil {
		http.Error(w, "Time series not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ts)
}

// parseTimeRange extracts time range from request.
func parseTimeRange(r *http.Request) (time.Time, time.Time) {
	now := time.Now()
	from := now.Add(-24 * time.Hour)
	to := now

	if f := r.URL.Query().Get("from"); f != "" {
		if t, err := time.Parse(time.RFC3339, f); err == nil {
			from = t
		}
	}

	if t := r.URL.Query().Get("to"); t != "" {
		if parsed, err := time.Parse(time.RFC3339, t); err == nil {
			to = parsed
		}
	}

	return from, to
}

// parseInterval parses duration string.
func parseInterval(s string, defaultVal time.Duration) time.Duration {
	if s == "" {
		return defaultVal
	}

	// Try to parse as number of minutes
	if minutes, err := strconv.Atoi(s); err == nil {
		return time.Duration(minutes) * time.Minute
	}

	// Try to parse as duration
	d, err := time.ParseDuration(s)
	if err != nil {
		return defaultVal
	}

	return d
}

// Layer provides analytics as a WAF layer.
type Layer struct {
	handler    *Handler
	collector  *Collector
	config     *LayerConfig
}

// LayerConfig for analytics layer.
type LayerConfig struct {
	Enabled bool   `yaml:"enabled"`
	Config  *Config `yaml:"analytics_config"`
}

// NewLayer creates a new analytics layer.
func NewLayer(cfg *LayerConfig) (*Layer, error) {
	if cfg == nil {
		cfg = &LayerConfig{
			Enabled: false,
			Config:  DefaultConfig(),
		}
	}

	if !cfg.Enabled {
		return &Layer{config: cfg}, nil
	}

	collector := NewCollector(cfg.Config)
	handler := NewHandler(collector)

	return &Layer{
		handler:   handler,
		collector: collector,
		config:    cfg,
	}, nil
}

// Name returns the layer name.
func (l *Layer) Name() string {
	return "analytics"
}

// Order returns the layer order.
func (l *Layer) Order() int {
	return 50 // Early, before most layers
}

// Process implements the layer interface.
func (l *Layer) Process(ctx interface{}) interface{} {
	if !l.config.Enabled || l.collector == nil {
		return nil
	}

	// Record metrics based on request/response
	// This would be called from the engine after request processing

	return nil
}

// RecordRequest records request metrics.
func (l *Layer) RecordRequest(duration time.Duration, statusCode int, blocked bool) {
	if !l.config.Enabled || l.collector == nil {
		return
	}

	// Record request metrics
	l.collector.Counter("requests_total", nil, 1)
	l.collector.Histogram("request_latency_ms", nil, float64(duration.Milliseconds()))

	if blocked {
		l.collector.Counter("requests_blocked", nil, 1)
	} else {
		l.collector.Counter("requests_allowed", nil, 1)
	}
}

// GetHandler returns the HTTP handler.
func (l *Layer) GetHandler() *Handler {
	return l.handler
}

// GetCollector returns the metrics collector.
func (l *Layer) GetCollector() *Collector {
	return l.collector
}

// GetStats returns analytics statistics.
func (l *Layer) GetStats() map[string]any {
	if l.collector == nil {
		return map[string]any{
			"enabled": false,
		}
	}
	return l.collector.GetAllMetrics()
}

// Close closes the layer.
func (l *Layer) Close() error {
	if l.collector != nil {
		return l.collector.Close()
	}
	return nil
}

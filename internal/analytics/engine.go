package analytics

import (
	"math"
	"sort"
	"time"
)

// Engine provides advanced analytics and trend analysis.
type Engine struct {
	collector *Collector
}

// NewEngine creates a new analytics engine.
func NewEngine(collector *Collector) *Engine {
	return &Engine{
		collector: collector,
	}
}

// TrafficStats represents traffic statistics.
type TrafficStats struct {
	TotalRequests      int64     `json:"total_requests"`
	BlockedRequests    int64     `json:"blocked_requests"`
	AllowedRequests    int64     `json:"allowed_requests"`
	ChallengedRequests int64     `json:"challenged_requests"`
	BlockedPercent     float64   `json:"blocked_percent"`
	AvgLatency         float64   `json:"avg_latency_ms"`
	P95Latency         float64   `json:"p95_latency_ms"`
	P99Latency         float64   `json:"p99_latency_ms"`
	RequestsPerSecond  float64   `json:"requests_per_second"`
	UniqueIPs          int64     `json:"unique_ips"`
	UniqueCountries    int       `json:"unique_countries"`
	TopAttackTypes     []AttackStat `json:"top_attack_types"`
}

// AttackStat represents attack type statistics.
type AttackStat struct {
	Type      string  `json:"type"`
	Count     int64   `json:"count"`
	Percent   float64 `json:"percent"`
}

// TrendPoint represents a data point in a trend.
type TrendPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// TrendAnalysis represents trend analysis results.
type TrendAnalysis struct {
	Metric      string       `json:"metric"`
	Period      string       `json:"period"`
	DataPoints  []TrendPoint `json:"data_points"`
	Slope       float64      `json:"slope"`
	Direction   string       `json:"direction"` // "increasing", "decreasing", "stable"
	ChangeRate  float64      `json:"change_rate"`
}

// GeoDistribution represents geographic traffic distribution.
type GeoDistribution struct {
	Countries    []CountryStat    `json:"countries"`
	Continents   []ContinentStat  `json:"continents"`
	TopCities    []CityStat       `json:"top_cities"`
}

// CountryStat represents country-level statistics.
type CountryStat struct {
	Code      string  `json:"code"`
	Name      string  `json:"name"`
	Requests  int64   `json:"requests"`
	Blocked   int64   `json:"blocked"`
	Percent   float64 `json:"percent"`
	Latitude  float64 `json:"lat,omitempty"`
	Longitude float64 `json:"lon,omitempty"`
}

// ContinentStat represents continent-level statistics.
type ContinentStat struct {
	Name     string  `json:"name"`
	Requests int64   `json:"requests"`
	Percent  float64 `json:"percent"`
}

// CityStat represents city-level statistics.
type CityStat struct {
	Name     string  `json:"name"`
	Country  string  `json:"country"`
	Requests int64   `json:"requests"`
}

// TopNItem represents a top-N item.
type TopNItem struct {
	Key   string  `json:"key"`
	Value float64 `json:"value"`
}

// GetTrafficStats returns overall traffic statistics.
func (e *Engine) GetTrafficStats(from, to time.Time) TrafficStats {
	stats := TrafficStats{
		TotalRequests:      e.collector.GetCounter("requests_total", nil),
		BlockedRequests:    e.collector.GetCounter("requests_blocked", nil),
		AllowedRequests:    e.collector.GetCounter("requests_allowed", nil),
		ChallengedRequests: e.collector.GetCounter("requests_challenged", nil),
	}

	if stats.TotalRequests > 0 {
		stats.BlockedPercent = float64(stats.BlockedRequests) / float64(stats.TotalRequests) * 100
	}

	// Latency statistics
	hist := e.collector.GetHistogram("request_latency_ms", nil)
	if hist.Count > 0 {
		stats.AvgLatency = hist.Mean
		stats.P95Latency = hist.Percentile(95)
		stats.P99Latency = hist.Percentile(99)
	}

	// Calculate RPS based on time range
	duration := to.Sub(from).Seconds()
	if duration > 0 {
		stats.RequestsPerSecond = float64(stats.TotalRequests) / duration
	}

	// Get attack type breakdown
	stats.TopAttackTypes = e.getAttackTypes(from, to)

	return stats
}

// getAttackTypes returns top attack types.
func (e *Engine) getAttackTypes(from, to time.Time) []AttackStat {
	attackTypes := []string{"sqli", "xss", "lfi", "cmdi", "xxe", "ssrf", "bot", "rate_limit"}
	var stats []AttackStat

	for _, attackType := range attackTypes {
		labels := map[string]string{"type": attackType}
		count := e.collector.GetCounter("attacks_total", labels)
		if count > 0 {
			stats = append(stats, AttackStat{
				Type:  attackType,
				Count: count,
			})
		}
	}

	// Sort by count descending
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Count > stats[j].Count
	})

	// Calculate percentages
	total := int64(0)
	for _, s := range stats {
		total += s.Count
	}
	for i := range stats {
		if total > 0 {
			stats[i].Percent = float64(stats[i].Count) / float64(total) * 100
		}
	}

	// Return top 5
	if len(stats) > 5 {
		stats = stats[:5]
	}

	return stats
}

// AnalyzeTrend performs trend analysis on a metric.
func (e *Engine) AnalyzeTrend(metric string, labels map[string]string, from, to time.Time, interval time.Duration) TrendAnalysis {
	ts := e.collector.GetTimeSeries(metric, labels, from, to)
	if ts == nil || len(ts.Points) < 2 {
		return TrendAnalysis{
			Metric: metric,
			Period: from.Format("2006-01-02") + " to " + to.Format("2006-01-02"),
		}
	}

	// Aggregate points by interval
	intervalSecs := int64(interval.Seconds())
	if intervalSecs <= 0 {
		intervalSecs = 1
	}
	buckets := make(map[int64][]float64)
	for _, p := range ts.Points {
		bucket := p.Timestamp.Unix() / intervalSecs
		buckets[bucket] = append(buckets[bucket], p.Value)
	}

	// Calculate bucket values (avg)
	var dataPoints []TrendPoint
	for bucket, values := range buckets {
		if len(values) > 0 {
			sum := 0.0
			for _, v := range values {
				sum += v
			}
			dataPoints = append(dataPoints, TrendPoint{
				Timestamp: time.Unix(bucket*int64(interval.Seconds()), 0),
				Value:     sum / float64(len(values)),
			})
		}
	}

	// Sort by timestamp
	sort.Slice(dataPoints, func(i, j int) bool {
		return dataPoints[i].Timestamp.Before(dataPoints[j].Timestamp)
	})

	// Calculate trend using linear regression
	slope, direction := e.calculateTrend(dataPoints)

	// Calculate change rate
	changeRate := 0.0
	if len(dataPoints) > 1 {
		first := dataPoints[0].Value
		last := dataPoints[len(dataPoints)-1].Value
		if first != 0 {
			changeRate = (last - first) / first * 100
		}
	}

	return TrendAnalysis{
		Metric:     metric,
		Period:     from.Format("2006-01-02") + " to " + to.Format("2006-01-02"),
		DataPoints: dataPoints,
		Slope:      slope,
		Direction:  direction,
		ChangeRate: changeRate,
	}
}

// calculateTrend calculates trend direction using linear regression.
func (e *Engine) calculateTrend(points []TrendPoint) (float64, string) {
	if len(points) < 2 {
		return 0, "stable"
	}

	n := float64(len(points))
	sumX, sumY, sumXY, sumX2 := 0.0, 0.0, 0.0, 0.0

	for i, p := range points {
		x := float64(i)
		y := p.Value
		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x
	}

	slope := (n*sumXY - sumX*sumY) / (n*sumX2 - sumX*sumX)

	// Determine direction
	direction := "stable"
	if math.Abs(slope) > 0.01 {
		if slope > 0 {
			direction = "increasing"
		} else {
			direction = "decreasing"
		}
	}

	return slope, direction
}

// GetGeoDistribution returns geographic traffic distribution.
func (e *Engine) GetGeoDistribution(from, to time.Time) GeoDistribution {
	geo := GeoDistribution{
		Countries:  []CountryStat{},
		Continents: []ContinentStat{},
		TopCities:  []CityStat{},
	}

	// Get all country metrics
	countries := e.getTopCountries(from, to)
	geo.Countries = countries

	// Aggregate by continent
	continentMap := make(map[string]int64)
	for _, c := range countries {
		continent := e.countryToContinent(c.Code)
		continentMap[continent] += c.Requests
	}

	for name, requests := range continentMap {
		geo.Continents = append(geo.Continents, ContinentStat{
			Name:     name,
			Requests: requests,
		})
	}

	// Sort continents by requests
	sort.Slice(geo.Continents, func(i, j int) bool {
		return geo.Continents[i].Requests > geo.Continents[j].Requests
	})

	// Calculate percentages
	total := int64(0)
	for _, c := range geo.Countries {
		total += c.Requests
	}
	for i := range geo.Countries {
		if total > 0 {
			geo.Countries[i].Percent = float64(geo.Countries[i].Requests) / float64(total) * 100
		}
	}
	for i := range geo.Continents {
		if total > 0 {
			geo.Continents[i].Percent = float64(geo.Continents[i].Requests) / float64(total) * 100
		}
	}

	return geo
}

// getTopCountries returns top countries by request count.
func (e *Engine) getTopCountries(from, to time.Time) []CountryStat {
	var countries []CountryStat

	// This would typically query the collector for country-specific metrics
	// For now, return empty (implementation depends on GeoIP integration)

	return countries
}

// countryToContinent maps country code to continent.
func (e *Engine) countryToContinent(code string) string {
	// Simplified mapping
	continents := map[string]string{
		"US": "North America", "CA": "North America", "MX": "North America",
		"GB": "Europe", "DE": "Europe", "FR": "Europe", "IT": "Europe", "ES": "Europe",
		"JP": "Asia", "CN": "Asia", "IN": "Asia", "KR": "Asia", "SG": "Asia",
		"AU": "Oceania", "NZ": "Oceania",
		"BR": "South America", "AR": "South America",
		"ZA": "Africa", "EG": "Africa", "NG": "Africa",
	}

	if continent, ok := continents[code]; ok {
		return continent
	}
	return "Unknown"
}

// GetTopN returns top N items for a metric.
func (e *Engine) GetTopN(metric string, n int, from, to time.Time) []TopNItem {
	// Get all series for this metric
	allMetrics := e.collector.GetAllMetrics()

	counters := allMetrics["counters"].(map[string]int64)

	var items []TopNItem
	for key, value := range counters {
		if key == metric || key == "requests_total" {
			items = append(items, TopNItem{
				Key:   key,
				Value: float64(value),
			})
		}
	}

	// Sort by value descending
	sort.Slice(items, func(i, j int) bool {
		return items[i].Value > items[j].Value
	})

	// Return top N
	if len(items) > n {
		items = items[:n]
	}

	return items
}

// GetAnomalyScore calculates anomaly score based on traffic patterns.
func (e *Engine) GetAnomalyScore(window time.Duration) float64 {
	now := time.Now()
	from := now.Add(-window)

	// Get current traffic rate
	currentStats := e.GetTrafficStats(from, now)
	currentRPS := currentStats.RequestsPerSecond

	// Get historical traffic rate (same window, 1 day ago)
	yesterdayFrom := from.Add(-24 * time.Hour)
	yesterdayTo := now.Add(-24 * time.Hour)
	yesterdayStats := e.GetTrafficStats(yesterdayFrom, yesterdayTo)
	yesterdayRPS := yesterdayStats.RequestsPerSecond

	// Calculate anomaly score based on deviation from historical
	if yesterdayRPS == 0 {
		if currentRPS > 0 {
			return 100 // Complete anomaly
		}
		return 0 // No traffic both days
	}

	deviation := math.Abs(currentRPS-yesterdayRPS) / yesterdayRPS * 100
	return math.Min(deviation, 100)
}

// ComparePeriods compares two time periods.
func (e *Engine) ComparePeriods(currentFrom, currentTo, previousFrom, previousTo time.Time) map[string]any {
	current := e.GetTrafficStats(currentFrom, currentTo)
	previous := e.GetTrafficStats(previousFrom, previousTo)

	return map[string]any{
		"current_period": map[string]any{
			"from":            currentFrom,
			"to":              currentTo,
			"total_requests":  current.TotalRequests,
			"blocked_percent": current.BlockedPercent,
			"avg_latency_ms":  current.AvgLatency,
		},
		"previous_period": map[string]any{
			"from":            previousFrom,
			"to":              previousTo,
			"total_requests":  previous.TotalRequests,
			"blocked_percent": previous.BlockedPercent,
			"avg_latency_ms":  previous.AvgLatency,
		},
		"changes": map[string]any{
			"requests_percent": calculatePercentChange(previous.TotalRequests, current.TotalRequests),
			"blocked_percent":  calculatePercentChangeFloat(previous.BlockedPercent, current.BlockedPercent),
			"latency_percent":  calculatePercentChangeFloat(previous.AvgLatency, current.AvgLatency),
		},
	}
}

// calculatePercentChange calculates percentage change.
func calculatePercentChange(old, new int64) float64 {
	if old == 0 {
		if new > 0 {
			return 100
		}
		return 0
	}
	return float64(new-old) / float64(old) * 100
}

// calculatePercentChangeFloat calculates percentage change for float64.
func calculatePercentChangeFloat(old, new float64) float64 {
	if old == 0 {
		if new > 0 {
			return 100
		}
		return 0
	}
	return (new - old) / old * 100
}

// GetDashboardData returns data for dashboard.
func (e *Engine) GetDashboardData() map[string]any {
	now := time.Now()

	// Last 24 hours
	last24h := e.GetTrafficStats(now.Add(-24*time.Hour), now)

	// Last 7 days
	last7d := e.GetTrafficStats(now.Add(-7*24*time.Hour), now)

	// Last 30 days
	last30d := e.GetTrafficStats(now.Add(-30*24*time.Hour), now)

	// Real-time (last 5 minutes)
	realtime := e.GetTrafficStats(now.Add(-5*time.Minute), now)

	// Anomaly score
	anomalyScore := e.GetAnomalyScore(1 * time.Hour)

	return map[string]any{
		"realtime": map[string]any{
			"requests_per_second": realtime.RequestsPerSecond,
			"active_ips":          realtime.UniqueIPs,
		},
		"last_24h": last24h,
		"last_7d":  last7d,
		"last_30d": last30d,
		"anomaly_score": anomalyScore,
		"geo_distribution": e.GetGeoDistribution(now.Add(-24*time.Hour), now),
		"top_attack_types": last24h.TopAttackTypes,
	}
}

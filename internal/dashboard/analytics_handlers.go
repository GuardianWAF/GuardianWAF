package dashboard

import (
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

func (d *Dashboard) registerAnalytics(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/analytics/dashboard", d.authWrap(d.handleAnalyticsDashboard))
	mux.HandleFunc("GET /api/v1/analytics/traffic", d.authWrap(d.handleAnalyticsTraffic))
	mux.HandleFunc("GET /api/v1/analytics/attacks", d.authWrap(d.handleAnalyticsAttacks))
	mux.HandleFunc("GET /api/v1/analytics/top", d.authWrap(d.handleAnalyticsTop))
	mux.HandleFunc("GET /api/v1/analytics/metrics", d.authWrap(d.handleAnalyticsMetrics))
	mux.HandleFunc("GET /api/v1/analytics/trends", d.authWrap(d.handleAnalyticsTrends))
	mux.HandleFunc("GET /api/v1/analytics/geo", d.authWrap(d.handleAnalyticsGeo))
	mux.HandleFunc("GET /api/v1/analytics/comparison", d.authWrap(d.handleAnalyticsComparison))
	mux.HandleFunc("GET /api/v1/analytics/timeseries", d.authWrap(d.handleAnalyticsTimeseries))
}

func (d *Dashboard) handleAnalyticsDashboard(w http.ResponseWriter, r *http.Request) {
	evts, _, err := d.analyticsEvents(r, 1000)
	if err != nil {
		writeError(w, http.StatusInternalServerError, sanitizeErr(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"traffic": d.analyticsTrafficPayload(evts),
		"attacks": d.analyticsAttackPayload(evts),
		"top":     d.analyticsTopPayload(evts, analyticsLimit(r, 10)),
		"metrics": d.analyticsMetricsPayload(),
	})
}

func (d *Dashboard) handleAnalyticsTraffic(w http.ResponseWriter, r *http.Request) {
	evts, _, err := d.analyticsEvents(r, 1000)
	if err != nil {
		writeError(w, http.StatusInternalServerError, sanitizeErr(err))
		return
	}
	writeJSON(w, http.StatusOK, d.analyticsTrafficPayload(evts))
}

func (d *Dashboard) handleAnalyticsAttacks(w http.ResponseWriter, r *http.Request) {
	evts, _, err := d.analyticsEvents(r, 1000)
	if err != nil {
		writeError(w, http.StatusInternalServerError, sanitizeErr(err))
		return
	}
	writeJSON(w, http.StatusOK, d.analyticsAttackPayload(evts))
}

func (d *Dashboard) handleAnalyticsTop(w http.ResponseWriter, r *http.Request) {
	evts, _, err := d.analyticsEvents(r, 1000)
	if err != nil {
		writeError(w, http.StatusInternalServerError, sanitizeErr(err))
		return
	}
	writeJSON(w, http.StatusOK, d.analyticsTopPayload(evts, analyticsLimit(r, 10)))
}

func (d *Dashboard) handleAnalyticsMetrics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, d.analyticsMetricsPayload())
}

func (d *Dashboard) handleAnalyticsTrends(w http.ResponseWriter, r *http.Request) {
	evts, _, err := d.analyticsEvents(r, 1000)
	if err != nil {
		writeError(w, http.StatusInternalServerError, sanitizeErr(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"metric":     firstNonEmpty(r.URL.Query().Get("metric"), "requests"),
		"interval":   firstNonEmpty(r.URL.Query().Get("interval"), "hour"),
		"timeseries": analyticsSeries(evts, firstNonEmpty(r.URL.Query().Get("interval"), "hour")),
	})
}

func (d *Dashboard) handleAnalyticsGeo(w http.ResponseWriter, r *http.Request) {
	evts, _, err := d.analyticsEvents(r, 1000)
	if err != nil {
		writeError(w, http.StatusInternalServerError, sanitizeErr(err))
		return
	}
	countries := make(map[string]int)
	for _, evt := range evts {
		key := evt.CountryCode
		if key == "" {
			key = evt.CountryName
		}
		if key == "" {
			key = "unknown"
		}
		countries[key]++
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"countries": countMapToRows(countries, analyticsLimit(r, 25)),
	})
}

func (d *Dashboard) handleAnalyticsComparison(w http.ResponseWriter, r *http.Request) {
	current, _, err := d.analyticsEvents(r, 1000)
	if err != nil {
		writeError(w, http.StatusInternalServerError, sanitizeErr(err))
		return
	}
	previousFilter := events.EventFilter{
		Limit:     1000,
		SortBy:    "timestamp",
		SortOrder: "desc",
	}
	q := r.URL.Query()
	if t, ok := parseTimeParam(q.Get("previous_from")); ok {
		previousFilter.Since = t
	} else {
		// Default the previous window to the immediately preceding period
		// of the same length as the current window; without this the
		// zero-valued filter queries all history while the response calls
		// it the "previous" period.
		window := analyticsWindowBounds(r)
		span := window.Until.Sub(window.Since)
		previousFilter.Since = window.Since.Add(-span)
		previousFilter.Until = window.Since
	}
	if t, ok := parseTimeParam(q.Get("previous_to")); ok {
		previousFilter.Until = t
	}
	previous, _, err := d.eventStore.Query(previousFilter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, sanitizeErr(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"current":  d.analyticsTrafficPayload(current),
		"previous": d.analyticsTrafficPayload(previous),
	})
}

func (d *Dashboard) handleAnalyticsTimeseries(w http.ResponseWriter, r *http.Request) {
	evts, _, err := d.analyticsEvents(r, 1000)
	if err != nil {
		writeError(w, http.StatusInternalServerError, sanitizeErr(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":   firstNonEmpty(r.URL.Query().Get("name"), "requests"),
		"points": analyticsSeries(evts, firstNonEmpty(r.URL.Query().Get("interval"), "hour")),
	})
}

// analyticsWindow is the resolved current analytics window.
type analyticsWindow struct {
	Since time.Time
	Until time.Time
}

// analyticsWindowBounds resolves the current window from query params:
// explicit from/to (or start/end) win, then a period offset anchored at
// the window end, and the fallback is the trailing 24 hours. Until
// defaults to now.
func analyticsWindowBounds(r *http.Request) analyticsWindow {
	q := r.URL.Query()
	var since time.Time
	if from := firstNonEmpty(q.Get("from"), q.Get("start")); from != "" {
		if t, ok := parseTimeParam(from); ok {
			since = t
		}
	}
	until := time.Now()
	if to := firstNonEmpty(q.Get("to"), q.Get("end")); to != "" {
		if t, ok := parseTimeParam(to); ok {
			until = t
		}
	}
	if since.IsZero() {
		if period := q.Get("period"); period != "" {
			since = until.Add(-parsePeriod(period))
		} else {
			since = until.Add(-24 * time.Hour)
		}
	}
	return analyticsWindow{Since: since, Until: until}
}

func (d *Dashboard) analyticsEvents(r *http.Request, defaultLimit int) ([]engine.Event, int, error) {
	window := analyticsWindowBounds(r)
	filter := events.EventFilter{
		Limit:     analyticsLimit(r, defaultLimit),
		SortBy:    "timestamp",
		SortOrder: "desc",
		Since:     window.Since,
		Until:     window.Until,
	}
	return d.eventStore.Query(filter)
}

func (d *Dashboard) analyticsMetricsPayload() map[string]any {
	s := d.engine.Stats()
	return map[string]any{
		"total_requests":      s.TotalRequests,
		"blocked_requests":    s.BlockedRequests,
		"challenged_requests": s.ChallengedRequests,
		"logged_requests":     s.LoggedRequests,
		"passed_requests":     s.PassedRequests,
		"avg_latency_us":      s.AvgLatencyUs,
	}
}

func (d *Dashboard) analyticsTrafficPayload(evts []engine.Event) map[string]any {
	requests := len(evts)
	actions := map[string]int{"pass": 0, "block": 0, "log": 0, "challenge": 0}
	for _, evt := range evts {
		actions[evt.Action.String()]++
	}
	return map[string]any{
		"requests": requests,
		"total":    requests,
		"actions":  actions,
	}
}

func (d *Dashboard) analyticsAttackPayload(evts []engine.Event) map[string]any {
	blocks := 0
	highScore := 0
	rules := make(map[string]int)
	for _, evt := range evts {
		if evt.Action == engine.ActionBlock {
			blocks++
		}
		if evt.Score >= 50 {
			highScore++
		}
		for _, finding := range evt.Findings {
			key := finding.DetectorName
			if key == "" {
				key = finding.Category
			}
			if key != "" {
				rules[key]++
			}
		}
	}
	return map[string]any{
		"blocks":     blocks,
		"attacks":    highScore,
		"top_rules":  countMapToRows(rules, 10),
		"total_seen": len(evts),
	}
}

func (d *Dashboard) analyticsTopPayload(evts []engine.Event, limit int) map[string]any {
	ips := make(map[string]int)
	paths := make(map[string]int)
	rules := make(map[string]int)
	for _, evt := range evts {
		if evt.ClientIP != "" {
			ips[evt.ClientIP]++
		}
		if evt.Path != "" {
			paths[evt.Path]++
		}
		for _, finding := range evt.Findings {
			key := finding.DetectorName
			if key == "" {
				key = finding.Category
			}
			if key != "" {
				rules[key]++
			}
		}
	}
	return map[string]any{
		"top_ips":   countMapToRows(ips, limit),
		"top_paths": countMapToRows(paths, limit),
		"top_rules": countMapToRows(rules, limit),
		"targets":   countMapToRows(paths, limit),
	}
}

func analyticsLimit(r *http.Request, fallback int) int {
	limit := fallback
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

func analyticsSeries(evts []engine.Event, interval string) []map[string]any {
	buckets := make(map[string]int)
	for _, evt := range evts {
		t := evt.Timestamp
		switch interval {
		case "day":
			t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
		case "minute":
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), 0, 0, t.Location())
		default: // "hour" and any unrecognized interval falls back to hourly buckets
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, t.Location())
		}
		buckets[t.Format(time.RFC3339)]++
	}
	return countMapToRows(buckets, 1000)
}

func countMapToRows(values map[string]int, limit int) []map[string]any {
	rows := make([]map[string]any, 0, len(values))
	for key, count := range values {
		rows = append(rows, map[string]any{"key": key, "count": count})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i]["count"].(int) == rows[j]["count"].(int) {
			return rows[i]["key"].(string) < rows[j]["key"].(string)
		}
		return rows[i]["count"].(int) > rows[j]["count"].(int)
	})
	if len(rows) > limit {
		return rows[:limit]
	}
	return rows
}

func parsePeriod(value string) time.Duration {
	switch value {
	case "7d":
		return 7 * 24 * time.Hour
	case "24h", "1d":
		return 24 * time.Hour
	case "30m":
		return 30 * time.Minute
	default:
		return time.Hour
	}
}

func parseTimeParam(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	if unixMs, err := strconv.ParseInt(value, 10, 64); err == nil {
		return time.UnixMilli(unixMs), true
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, true
	}
	return time.Time{}, false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

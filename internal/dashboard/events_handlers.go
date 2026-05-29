package dashboard

import (

"fmt"
"github.com/guardianwaf/guardianwaf/internal/engine"
"github.com/guardianwaf/guardianwaf/internal/events"
"net/http"
"time"
	"strconv"
	"strings"
)


// --- Stats ---

func (d *Dashboard) handleGetStats(w http.ResponseWriter, r *http.Request) {
	stats := d.engine.Stats()
	result := map[string]any{
		"total_requests":      stats.TotalRequests,
		"blocked_requests":    stats.BlockedRequests,
		"challenged_requests": stats.ChallengedRequests,
		"logged_requests":     stats.LoggedRequests,
		"passed_requests":     stats.PassedRequests,
		"avg_latency_us":      stats.AvgLatencyUs,
	}
	if d.alertingStats != nil {
		result["alerting"] = d.alertingStats.GetAlertingStats()
	}
	writeJSON(w, http.StatusOK, result)
}

// --- Events ---

func (d *Dashboard) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	limit := 50
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = min(n, 1000)
		}
	}

	offset := 0
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	filter := events.EventFilter{
		Limit:     limit,
		Offset:    offset,
		Action:    q.Get("action"),
		ClientIP:  q.Get("client_ip"),
		Path:      q.Get("path"),
		SortBy:    q.Get("sort_by"),
		SortOrder: q.Get("sort_order"),
	}

	if v := q.Get("min_score"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			filter.MinScore = n
		}
	}

	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Since = t
		}
	}
	if v := q.Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Until = t
		}
	}

	evts, total, err := d.eventStore.Query(filter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": sanitizeErr(err)})
		return
	}

	// Cap offset to prevent out-of-range enumeration
	if offset > total {
		offset = total
		evts = nil
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"events": evts,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

func (d *Dashboard) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing event ID"})
		return
	}

	evt, err := d.eventStore.Get(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "event not found"})
		return
	}

	writeJSON(w, http.StatusOK, evt)
}

// handleExportEvents exports events to JSON or CSV format.
// Query params: format (json|csv), action, client_ip, path, min_score, since, until
func (d *Dashboard) handleExportEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := q.Get("format")
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid format, use 'json' or 'csv'"})
		return
	}

	// Build filter (same as handleGetEvents but with higher limit for exports)
	filter := events.EventFilter{
		Action:    q.Get("action"),
		ClientIP:  q.Get("client_ip"),
		Path:      q.Get("path"),
		SortBy:    q.Get("sort_by"),
		SortOrder: q.Get("sort_order"),
	}

	// Export limit: default 10000, max 50000
	filter.Limit = 10000
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			filter.Limit = min(n, 50000)
		}
	}

	if v := q.Get("min_score"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			filter.MinScore = n
		}
	}
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Since = t
		}
	}
	if v := q.Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Until = t
		}
	}

	evts, _, err := d.eventStore.Query(filter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": sanitizeErr(err)})
		return
	}

	switch format {
	case "csv":
		d.writeEventsCSV(w, evts)
	default:
		d.writeEventsJSON(w, evts)
	}
}

func (d *Dashboard) writeEventsJSON(w http.ResponseWriter, evts []engine.Event) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\"events.json\"")
	writeJSON(w, http.StatusOK, map[string]any{"events": evts, "count": len(evts)})
}

func (d *Dashboard) writeEventsCSV(w http.ResponseWriter, evts []engine.Event) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=\"events.csv\"")

	// CSV header
	header := "timestamp,event_id,client_ip,method,path,action,score,user_agent,findings\n"
	_, _ = w.Write([]byte(header)) // nolint:errcheck // CSV export write; error ignored

	// CSV rows
	for _, e := range evts {
		findings := make([]string, len(e.Findings))
		for i, f := range e.Findings {
			findings[i] = f.DetectorName + ":" + f.Description
		}
		findingsStr := strings.Join(findings, "; ")
		line := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%d,\"%s\",\"%s\"\n",
			e.Timestamp.Format(time.RFC3339),
			e.ID,
			e.ClientIP,
			e.Method,
			escapeCSV(e.Path),
			e.Action.String(),
			e.Score,
			escapeCSV(e.UserAgent),
			escapeCSV(findingsStr),
		)
		_, _ = w.Write([]byte(line)) // nolint:errcheck // CSV export write; error ignored
	}
}

// escapeCSV escapes a string for CSV output.
// Also prevents formula injection by prefixing dangerous leading characters
// with a single quote, so spreadsheet applications don't execute formulas.
func escapeCSV(s string) string {
	if len(s) > 0 {
		switch s[0] {
		case '=', '+', '-', '@', '\t', '\r':
			s = "'" + s
		}
	}
	if strings.ContainsAny(s, ",\"\n\r") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

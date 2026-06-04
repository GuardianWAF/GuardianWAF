package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func setupAccessLogging(eng *engine.Engine, cfg *config.Config) {
	if !cfg.Logging.LogBlocked && !cfg.Logging.LogAllowed {
		return
	}
	logBlocked := cfg.Logging.LogBlocked
	logAllowed := cfg.Logging.LogAllowed
	eng.SetAccessLog(func(entry engine.AccessLogEntry) {
		isBlocked := entry.Action == "block" || entry.Action == "challenge"
		if isBlocked && !logBlocked {
			return
		}
		if !isBlocked && !logAllowed {
			return
		}
		if cfg.Logging.Format == "json" {
			_ = json.NewEncoder(os.Stdout).Encode(struct {
				Timestamp  string `json:"ts"`
				ClientIP   string `json:"ip"`
				Method     string `json:"method"`
				Path       string `json:"path"`
				StatusCode int    `json:"status"`
				Action     string `json:"action"`
				Score      int    `json:"score"`
				Duration   string `json:"dur_us"`
				UserAgent  string `json:"ua"`
				Findings   int    `json:"findings"`
				RequestID  string `json:"request_id"`
				TenantID   string `json:"tenant_id,omitempty"`
			}{
				Timestamp:  entry.Timestamp,
				ClientIP:   entry.ClientIP,
				Method:     entry.Method,
				Path:       entry.Path,
				StatusCode: entry.StatusCode,
				Action:     entry.Action,
				Score:      entry.Score,
				Duration:   entry.Duration,
				UserAgent:  entry.UserAgent,
				Findings:   entry.Findings,
				RequestID:  entry.RequestID,
				TenantID:   entry.TenantID,
			})
		} else {
			fmt.Fprintf(os.Stdout, "%s %s %s %s %d %s score=%d dur=%sus findings=%d\n",
				entry.Timestamp, sanitizeLogField(entry.ClientIP), entry.Method, sanitizeLogField(entry.Path),
				entry.StatusCode, entry.Action, entry.Score, entry.Duration, entry.Findings)
		}
	})
	eng.Logs.Infof("Access logging enabled (blocked=%v, allowed=%v, format=%s)", logBlocked, logAllowed, cfg.Logging.Format)
}

func registerMetricsHandler(mux *http.ServeMux, eng *engine.Engine) {
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		s := eng.Stats()
		fmt.Fprintf(w, "# HELP guardianwaf_requests_total Total number of requests processed.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_requests_total counter\n")
		fmt.Fprintf(w, "guardianwaf_requests_total %d\n", s.TotalRequests)
		fmt.Fprintf(w, "# HELP guardianwaf_requests_blocked_total Total number of blocked requests.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_requests_blocked_total counter\n")
		fmt.Fprintf(w, "guardianwaf_requests_blocked_total %d\n", s.BlockedRequests)
		fmt.Fprintf(w, "# HELP guardianwaf_requests_challenged_total Total number of challenged requests.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_requests_challenged_total counter\n")
		fmt.Fprintf(w, "guardianwaf_requests_challenged_total %d\n", s.ChallengedRequests)
		fmt.Fprintf(w, "# HELP guardianwaf_requests_logged_total Total number of logged (suspicious) requests.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_requests_logged_total counter\n")
		fmt.Fprintf(w, "guardianwaf_requests_logged_total %d\n", s.LoggedRequests)
		fmt.Fprintf(w, "# HELP guardianwaf_requests_passed_total Total number of passed requests.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_requests_passed_total counter\n")
		fmt.Fprintf(w, "guardianwaf_requests_passed_total %d\n", s.PassedRequests)
		fmt.Fprintf(w, "# HELP guardianwaf_latency_avg_microseconds Average request latency in microseconds.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_latency_avg_microseconds gauge\n")
		fmt.Fprintf(w, "guardianwaf_latency_avg_microseconds %d\n", s.AvgLatencyUs)
	})
}

// sanitizeLogField strips control characters (0x00-0x1F, 0x7F) from a string
// to prevent log injection via ANSI escape sequences or other control chars
// in user-controlled fields (path, user-agent, etc.).
func sanitizeLogField(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7F {
			return -1
		}
		return r
	}, s)
}

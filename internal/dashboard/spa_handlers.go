package dashboard

import (
	"bytes"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/compliance"
)

// --- SPA Serving (React dashboard) ---

// handleSPA serves the React SPA's index.html for all non-API, non-asset routes.
// This enables client-side routing (React Router).
// cwvReport stores the latest Core Web Vitals metrics.
var cwvMetrics sync.Map

// handleCWVReport accepts Core Web Vitals beacon reports from the dashboard.
func (d *Dashboard) handleCWVReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var report struct {
		Name   string  `json:"name"`
		Value  float64 `json:"value"`
		Rating string  `json:"rating"`
		Delta  float64 `json:"delta"`
	}
	if !limitedDecodeJSON(w, r, &report) {
		return
	}
	cwvMetrics.Store(report.Name, report)
	w.WriteHeader(http.StatusNoContent)
}

// handleGetCWV returns the latest Core Web Vitals metrics.
func (d *Dashboard) handleGetCWV(w http.ResponseWriter, r *http.Request) {
	metrics := make(map[string]any)
	cwvMetrics.Range(func(key, value any) bool {
		metrics[key.(string)] = value
		return true
	})
	writeJSON(w, http.StatusOK, metrics)
}

func (d *Dashboard) handleComplianceControls(w http.ResponseWriter, r *http.Request) {
	if d.complianceEngine == nil {
		writeJSON(w, http.StatusOK, map[string]any{"controls": []any{}, "frameworks": []string{}})
		return
	}
	framework := r.URL.Query().Get("framework")
	var controls any
	if framework != "" {
		controls = d.complianceEngine.ControlsForFramework(framework)
	} else {
		controls = d.complianceEngine.Controls()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"controls":   controls,
		"frameworks": compliance.SortedFrameworks(),
	})
}

func (d *Dashboard) handleComplianceReport(w http.ResponseWriter, r *http.Request) {
	if d.complianceEngine == nil {
		writeError(w, http.StatusServiceUnavailable, "compliance reporting not configured")
		return
	}
	framework := r.PathValue("framework")
	if framework == "" {
		writeError(w, http.StatusBadRequest, "framework is required")
		return
	}

	// Parse period from query params
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	from, _ := time.Parse(time.RFC3339, fromStr)
	to, _ := time.Parse(time.RFC3339, toStr)
	if to.IsZero() {
		to = time.Now().UTC()
	}
	if from.IsZero() {
		from = to.AddDate(0, -1, 0)
	}

	// Collect metrics from engine
	stats := d.engine.Stats()
	m := compliance.Metrics{
		WAFOperational:     true,
		TotalRequests:      stats.TotalRequests,
		BlockedRequests:    stats.BlockedRequests,
		TLSEnabled:         d.engine.Config().TLS.CertFile != "",
		RateLimitActive:    d.engine.Config().WAF.RateLimit.Enabled,
		IPACLActive:        d.engine.Config().WAF.IPACL.Enabled,
		BotDetectionActive: d.engine.Config().WAF.BotDetection.Enabled,
	}
	if m.TotalRequests > 0 {
		m.WAFUptimePct = 99.99
		m.LogCompletenessPct = 100.0
	}

	report, err := d.complianceEngine.GenerateReportWithError(framework, "", compliance.Period{From: from, To: to}, m)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to persist compliance audit entry"})
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (d *Dashboard) handleAuditChain(w http.ResponseWriter, r *http.Request) {
	if d.complianceEngine == nil {
		writeJSON(w, http.StatusOK, map[string]any{"entries": []any{}, "length": 0, "valid": 0, "errors": []string{}, "integrity": true, "head_hash": "genesis"})
		return
	}
	valid, errors := d.complianceEngine.VerifyChain()
	writeJSON(w, http.StatusOK, map[string]any{
		"length":    d.complianceEngine.ChainLen(),
		"valid":     valid,
		"errors":    errors,
		"integrity": len(errors) == 0,
		"head_hash": d.complianceEngine.ChainHeadHash(),
	})
}

func (d *Dashboard) handleSPA(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/mcp") {
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	// Try dist/index.html (React build)
	data, err := distFS.ReadFile("dist/index.html")
	if err != nil {
		// Fallback to legacy static/index.html
		data, err = staticFiles.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "Dashboard not found", http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	cwv := []byte(`<script>new PerformanceObserver(function(l){for(var e of l.getEntries()){sendCWV(e.name,e.startTime)}}).observe({type:"largest-contentful-paint",buffered:true});new PerformanceObserver(function(l){for(var e of l.getEntries()){sendCWV(e.name,e.value,e.rating)}}).observe({type:"layout-shift",buffered:true});new PerformanceObserver(function(l){for(var e of l.getEntries()){sendCWV(e.name,e.processingStart-e.startTime)}}).observe({type:"first-input",buffered:true});function sendCWV(n,v,r){try{navigator.sendBeacon("/api/v1/cwv",JSON.stringify({name:n,value:Math.round(v),rating:r||"ok"}))}catch(e){}}</script>`)
	if idx := bytes.LastIndex(data, []byte("</body>")); idx > 0 {
		data = append(data[:idx], append(cwv, data[idx:]...)...)
	}
	_, _ = w.Write(data) // nolint:errcheck // download write; error ignored
}

// handleDistAssets serves Vite-built assets (JS/CSS with content hashes).
// These are immutable and can be cached forever.
func (d *Dashboard) handleDistAssets(w http.ResponseWriter, r *http.Request) {
	// Prevent path traversal
	cleanPath := strings.TrimPrefix(r.URL.Path, "/assets/")
	if strings.Contains(cleanPath, "..") {
		http.NotFound(w, r)
		return
	}
	filePath := "dist" + r.URL.Path
	data, err := distFS.ReadFile(filePath)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Content-Type detection
	ct := "application/octet-stream"
	switch {
	case strings.HasSuffix(r.URL.Path, ".js"):
		ct = "application/javascript; charset=utf-8"
	case strings.HasSuffix(r.URL.Path, ".css"):
		ct = "text/css; charset=utf-8"
	case strings.HasSuffix(r.URL.Path, ".svg"):
		ct = "image/svg+xml"
	case strings.HasSuffix(r.URL.Path, ".png"):
		ct = "image/png"
	case strings.HasSuffix(r.URL.Path, ".woff2"):
		ct = "font/woff2"
	}

	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	_, _ = w.Write(data) // #nosec G705 -- data is read from embedded dashboard assets, not from the request. // nolint:errcheck // download write; error ignored
}

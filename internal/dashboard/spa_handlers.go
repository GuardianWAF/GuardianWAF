package dashboard

import (
	"bytes"
	"net/http"
	"strings"
	"sync"
)

// --- SPA Serving (React dashboard) ---

// handleSPA serves the React SPA's index.html for all non-API, non-asset routes.
// This enables client-side routing (React Router).
// cwvReport stores the latest Core Web Vitals metrics.
var cwvMetrics sync.Map

// knownCWVMetrics is the fixed set of Core Web Vitals metric names. The CWV
// beacon endpoint is unauthenticated, so the map key must be constrained to
// this allowlist — otherwise an attacker could store unbounded unique keys and
// exhaust memory.
var knownCWVMetrics = map[string]struct{}{
	"CLS":  {},
	"FCP":  {},
	"FID":  {},
	"INP":  {},
	"LCP":  {},
	"TTFB": {},
}

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
	if _, ok := knownCWVMetrics[report.Name]; !ok {
		// Unknown metric names are dropped to bound map cardinality.
		w.WriteHeader(http.StatusNoContent)
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

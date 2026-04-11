package clientside

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
)

const maxReports = 1000

// ClientReport represents a report from the injected security agent.
type ClientReport struct {
	Type string         `json:"type"`
	Data map[string]any `json:"data"`
	URL  string         `json:"url"`
	TS   int64          `json:"ts"`
}

// ReportHandler collects and serves client-side security reports.
type ReportHandler struct {
	mu      sync.RWMutex
	reports []ClientReport
}

// NewReportHandler creates a new report handler.
func NewReportHandler() *ReportHandler {
	return &ReportHandler{
		reports: make([]ClientReport, 0, maxReports),
	}
}

// ServeHTTP handles POST /_guardian/report.
func (h *ReportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB max
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var report ClientReport
	if err := json.Unmarshal(body, &report); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	if len(h.reports) >= maxReports {
		h.reports = h.reports[1:]
	}
	h.reports = append(h.reports, report)
	h.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

// ServeCSPReport handles POST /_guardian/csp-report.
func (h *ReportHandler) ServeCSPReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	report := ClientReport{
		Type: "csp_violation",
		Data: map[string]any{"raw": string(body)},
		URL:  r.Header.Get("Referer"),
		TS:   time.Now().UnixMilli(),
	}

	h.mu.Lock()
	if len(h.reports) >= maxReports {
		h.reports = h.reports[1:]
	}
	h.reports = append(h.reports, report)
	h.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

// Reports returns a copy of all collected reports.
func (h *ReportHandler) Reports() []ClientReport {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]ClientReport, len(h.reports))
	copy(out, h.reports)
	return out
}

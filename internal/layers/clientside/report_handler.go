package clientside

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"
)

const (
	maxReports         = 1000
	maxReportBodyBytes = 1 << 20
)

var errReportBodyTooLarge = errors.New("client-side report body too large")

// ClientReport represents a report from the injected security agent.
type ClientReport struct {
	Type string         `json:"type"`
	Data map[string]any `json:"data"`
	URL  string         `json:"url"`
	TS   int64          `json:"ts"`
}

// storedReport is a report plus its insertion order, so the two per-class
// queues below can be merged back into one chronological view.
type storedReport struct {
	seq uint64
	r   ClientReport
}

// cspReportType is the Type ServeCSPReport stamps on browser CSP violations.
const cspReportType = "csp_violation"

// ReportHandler collects and serves client-side security reports.
//
// The two ingest paths keep SEPARATE queues because their volumes and values
// are wildly asymmetric, and they previously shared one ring:
//
//   - /_guardian/report carries the agent's routine telemetry — one entry per
//     fetch(), XHR open, and form submit. MonitorDOM and MonitorNetwork both
//     default to true, so this is high-volume by design.
//   - /_guardian/csp-report carries browser CSP violations: low-volume,
//     high-value security EVIDENCE, and the only thing the dashboard's
//     /api/clientside/csp-reports serves.
//
// With one shared ring, ordinary page traffic evicted the recorded violations
// before an operator could review them, and nothing reported the loss. Each
// queue is now bounded at maxReports and eviction prefers the oldest entry of
// the SAME class, so telemetry can never displace CSP evidence. The total
// entry count is still capped at maxReports, preserving the memory bound.
//
// Class membership comes from the INGEST PATH, never from the client-supplied
// Type, so a POST to /_guardian/report cannot promote itself into the
// evidence queue and displace real violations.
type ReportHandler struct {
	mu       sync.RWMutex
	evidence []storedReport // /_guardian/csp-report
	telem    []storedReport // /_guardian/report
	seq      uint64
}

// appendLocked adds a report to the class selected by evidence, evicting the
// oldest same-class entry once total occupancy reaches maxReports. Falls back
// to the other class only when the incoming class is empty, so the total is
// always bounded by maxReports. Caller must hold h.mu.
func (h *ReportHandler) appendLocked(r ClientReport, evidence bool) {
	h.seq++
	entry := storedReport{seq: h.seq, r: r}

	if len(h.evidence)+len(h.telem) >= maxReports {
		if evidence && len(h.evidence) > 0 {
			h.evidence = h.evidence[1:]
		} else if !evidence && len(h.telem) > 0 {
			h.telem = h.telem[1:]
		} else if len(h.evidence) > 0 {
			h.evidence = h.evidence[1:]
		} else {
			h.telem = h.telem[1:]
		}
	}

	if evidence {
		h.evidence = append(h.evidence, entry)
	} else {
		h.telem = append(h.telem, entry)
	}
}

// NewReportHandler creates a new report handler.
func NewReportHandler() *ReportHandler {
	return &ReportHandler{
		evidence: make([]storedReport, 0, maxReports),
		telem:    make([]storedReport, 0, maxReports),
	}
}

// ServeHTTP handles POST /_guardian/report.
func (h *ReportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := readReportBody(r.Body)
	if err != nil {
		if errors.Is(err, errReportBodyTooLarge) {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var report ClientReport
	if err := json.Unmarshal(body, &report); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	h.appendLocked(report, false)
	h.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

// ServeCSPReport handles POST /_guardian/csp-report.
func (h *ReportHandler) ServeCSPReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := readReportBody(r.Body)
	if err != nil {
		if errors.Is(err, errReportBodyTooLarge) {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	report := ClientReport{
		Type: cspReportType,
		Data: map[string]any{"raw": string(body)},
		URL:  r.Header.Get("Referer"),
		TS:   time.Now().UnixMilli(),
	}

	h.mu.Lock()
	h.appendLocked(report, true)
	h.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

func readReportBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxReportBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxReportBodyBytes {
		return nil, fmt.Errorf("%w: exceeds %d bytes", errReportBodyTooLarge, maxReportBodyBytes)
	}
	return body, nil
}

// Reports returns a copy of all collected reports, oldest-first, merged across
// the evidence and telemetry queues so callers see one chronological stream
// regardless of which ingest endpoint produced each entry.
func (h *ReportHandler) Reports() []ClientReport {
	h.mu.RLock()
	defer h.mu.RUnlock()

	merged := make([]storedReport, 0, len(h.evidence)+len(h.telem))
	merged = append(merged, h.evidence...)
	merged = append(merged, h.telem...)
	slices.SortFunc(merged, func(a, b storedReport) int {
		return cmp.Compare(a.seq, b.seq)
	})

	out := make([]ClientReport, len(merged))
	for i, e := range merged {
		out[i] = e.r
	}
	return out
}

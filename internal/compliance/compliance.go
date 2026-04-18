// Package compliance provides compliance reporting for PCI DSS, GDPR, SOC 2, and ISO 27001.
// It evaluates WAF metrics against mapped control requirements and generates structured reports.
package compliance

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// Control status constants.
const (
	StatusPassing       = "passing"
	StatusFailing       = "failing"
	StatusNotApplicable = "not_applicable"
	StatusNoEvidence    = "no_evidence"
)

// Framework identifiers.
const (
	FrameworkPCI  = "pci_dss"
	FrameworkGDPR = "gdpr"
	FrameworkSOC2 = "soc2"
	FrameworkISO  = "iso27001"
)

// Control represents a single compliance control mapped to WAF capabilities.
type Control struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Frameworks     []string       `json:"frameworks"`
	Evidence       []EvidenceSpec `json:"evidence"`
	PassingCriteria []Criterion    `json:"passing_criteria"`
}

// EvidenceSpec describes what evidence supports this control.
type EvidenceSpec struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

// Criterion defines a passing condition for a control.
type Criterion struct {
	Metric    string  `json:"metric"`
	Operator  string  `json:"operator"` // ">=", "<=", "==", ">", "<"
	Threshold float64 `json:"threshold"`
}

// ControlResult holds the evaluation result for a single control.
type ControlResult struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Status   string                 `json:"status"`
	Evidence map[string]any         `json:"evidence,omitempty"`
}

// Report represents a generated compliance report.
type Report struct {
	ReportID    string          `json:"report_id"`
	GeneratedAt time.Time       `json:"generated_at"`
	Period      Period          `json:"period"`
	TenantID    string          `json:"tenant_id,omitempty"`
	Framework   string          `json:"framework"`
	Summary     ReportSummary   `json:"summary"`
	Controls    []ControlResult `json:"controls"`
	ChainHash   string          `json:"chain_hash,omitempty"`
}

// Period defines a time range for a compliance report.
type Period struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// ReportSummary contains aggregate pass/fail counts.
type ReportSummary struct {
	ControlsPassing       int    `json:"controls_passing"`
	ControlsFailing       int    `json:"controls_failing"`
	ControlsNotApplicable int    `json:"controls_not_applicable"`
	OverallStatus         string `json:"overall_status"` // "passing", "partial", "failing"
}

// Metrics provides the current WAF metrics for control evaluation.
type Metrics struct {
	WAFOperational      bool    `json:"waf_operational"`
	WAFUptimePct        float64 `json:"waf_uptime_pct"`
	TotalRequests       int64   `json:"total_requests"`
	BlockedRequests     int64   `json:"blocked_requests"`
	LoggedRequests      int64   `json:"logged_requests"`
	LogCompletenessPct  float64 `json:"log_completeness_pct"`
	DLPBlocksInPeriod   int64   `json:"dlp_blocks_in_period"`
	AlertCount          int64   `json:"alert_count"`
	AlertResponseP95Min float64 `json:"alert_response_p95_min"`
	TLSEnabled          bool    `json:"tls_enabled"`
	MultiTenantEnabled  bool    `json:"multi_tenant_enabled"`
	RateLimitActive     bool    `json:"rate_limit_active"`
	IPACLActive         bool    `json:"ip_acl_active"`
	BotDetectionActive  bool    `json:"bot_detection_active"`
	GeoIPActive         bool    `json:"geoip_active"`
	CorsActive          bool    `json:"cors_active"`
}

// ChainEntry represents a single entry in the hash-chained audit trail.
type ChainEntry struct {
	Index    int       `json:"index"`
	Time     time.Time `json:"time"`
	Type     string    `json:"type"`
	Data     any       `json:"data"`
	PrevHash string    `json:"prev_hash"`
	Hash     string    `json:"hash"`
}

// Engine is the core compliance evaluation engine.
type Engine struct {
	mu       sync.RWMutex
	config   config.ComplianceConfig
	controls []Control
	chain    []ChainEntry
	lastHash string
	file     *os.File // JSONL persistence file (nil if no persist_path configured)
}

// NewEngine creates a new compliance engine with built-in controls.
func NewEngine(cfg config.ComplianceConfig) *Engine {
	e := &Engine{
		config:   cfg,
		controls: builtinControls(),
		lastHash: "genesis",
	}
	e.replayChain(cfg.AuditTrail.PersistPath)
	if cfg.AuditTrail.PersistPath != "" {
		f, err := os.OpenFile(cfg.AuditTrail.PersistPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err == nil {
			e.file = f
		}
	}
	return e
}

// Close flushes and closes the persistence file.
func (e *Engine) Close() {
	if e.file != nil {
		e.file.Sync()
		e.file.Close()
	}
}

// replayChain loads audit chain entries from a JSONL file on startup.
func (e *Engine) replayChain(path string) {
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		var entry ChainEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		e.chain = append(e.chain, entry)
		e.lastHash = entry.Hash
	}
}

// Controls returns all registered controls.
func (e *Engine) Controls() []Control {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Control, len(e.controls))
	copy(out, e.controls)
	return out
}

// ControlsForFramework returns controls matching a specific framework.
func (e *Engine) ControlsForFramework(framework string) []Control {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var result []Control
	for _, c := range e.controls {
		for _, fw := range c.Frameworks {
			if fw == framework {
				result = append(result, c)
				break
			}
		}
	}
	return result
}

// Evaluate evaluates all controls for a framework against the given metrics.
func (e *Engine) Evaluate(framework string, m Metrics) []ControlResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var results []ControlResult
	for _, c := range e.controls {
		matched := false
		for _, fw := range c.Frameworks {
			if fw == framework {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		cr := ControlResult{
			ID:   c.ID,
			Name: c.Name,
		}

		evidence := collectEvidence(c, m)
		cr.Evidence = evidence

		if len(c.PassingCriteria) == 0 {
			cr.Status = StatusNotApplicable
		} else if evaluateCriteria(c.PassingCriteria, m) {
			cr.Status = StatusPassing
		} else {
			cr.Status = StatusFailing
		}

		results = append(results, cr)
	}
	return results
}

// GenerateReport creates a compliance report for a framework and time period.
func (e *Engine) GenerateReport(framework, tenantID string, period Period, m Metrics) Report {
	results := e.Evaluate(framework, m)

	summary := ReportSummary{}
	for _, r := range results {
		switch r.Status {
		case StatusPassing:
			summary.ControlsPassing++
		case StatusFailing:
			summary.ControlsFailing++
		case StatusNotApplicable:
			summary.ControlsNotApplicable++
		}
	}

	switch {
	case summary.ControlsFailing == 0 && summary.ControlsPassing > 0:
		summary.OverallStatus = "passing"
	case summary.ControlsFailing > 0 && summary.ControlsPassing > 0:
		summary.OverallStatus = "partial"
	case summary.ControlsPassing == 0:
		summary.OverallStatus = "failing"
	}

	report := Report{
		ReportID:    fmt.Sprintf("rpt_%s_%s_%s", framework, period.From.Format("20060102"), period.To.Format("20060102")),
		GeneratedAt: time.Now().UTC(),
		Period:      period,
		TenantID:    tenantID,
		Framework:   framework,
		Summary:     summary,
		Controls:    results,
	}

	if e.config.AuditTrail.Enabled {
		entry := e.AppendChain("report_generated", report)
		report.ChainHash = entry.Hash
	}

	return report
}

// ActiveFrameworks returns the list of enabled frameworks.
func (e *Engine) ActiveFrameworks() []string {
	if len(e.config.Frameworks) > 0 {
		return e.config.Frameworks
	}
	return []string{FrameworkPCI, FrameworkGDPR, FrameworkSOC2, FrameworkISO}
}

// AppendChain adds an entry to the hash-chained audit trail.
func (e *Engine) AppendChain(entryType string, data any) ChainEntry {
	e.mu.Lock()
	defer e.mu.Unlock()

	entry := ChainEntry{
		Index:    len(e.chain),
		Time:     time.Now().UTC(),
		Type:     entryType,
		Data:     data,
		PrevHash: e.lastHash,
	}

	// Compute hash: SHA-256(index + time + type + JSON(data) + prevHash)
	hasher := sha256.New()
	fmt.Fprintf(hasher, "%d|%s|%s|", entry.Index, entry.Time.Format(time.RFC3339Nano), entry.Type)
	if dataBytes, err := json.Marshal(data); err == nil {
		hasher.Write(dataBytes)
	}
	fmt.Fprintf(hasher, "|%s", entry.PrevHash)
	entry.Hash = hex.EncodeToString(hasher.Sum(nil))

	e.chain = append(e.chain, entry)
	e.lastHash = entry.Hash

	// Append to JSONL file
	if e.file != nil {
		if data, err := json.Marshal(entry); err == nil {
			e.file.Write(data)
			e.file.Write([]byte("\n"))
		}
	}

	return entry
}

// VerifyChain verifies the integrity of the entire audit chain.
// Returns the number of valid entries and any errors found.
func (e *Engine) VerifyChain() (valid int, errors []string) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	prevHash := "genesis"
	for i, entry := range e.chain {
		if entry.PrevHash != prevHash {
			errors = append(errors, fmt.Sprintf("entry %d: prev_hash mismatch (expected %s, got %s)", i, prevHash, entry.PrevHash))
			continue
		}

		hasher := sha256.New()
		fmt.Fprintf(hasher, "%d|%s|%s|", entry.Index, entry.Time.Format(time.RFC3339Nano), entry.Type)
		if dataBytes, err := json.Marshal(entry.Data); err == nil {
			hasher.Write(dataBytes)
		}
		fmt.Fprintf(hasher, "|%s", entry.PrevHash)
		expected := hex.EncodeToString(hasher.Sum(nil))

		if entry.Hash != expected {
			errors = append(errors, fmt.Sprintf("entry %d: hash mismatch", i))
			continue
		}

		prevHash = entry.Hash
		valid++
	}
	return valid, errors
}

// ChainLen returns the number of entries in the audit chain.
func (e *Engine) ChainLen() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.chain)
}

// ReportJSON serializes a report to JSON.
func ReportJSON(r Report) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// ReportCSV generates CSV output from a report.
func ReportCSV(r Report) string {
	var sb strings.Builder
	sb.WriteString("control_id,control_name,status\n")
	for _, c := range r.Controls {
		sb.WriteString(fmt.Sprintf("%s,%s,%s\n", c.ID, c.Name, c.Status))
	}
	return sb.String()
}

// evaluateCriteria checks all criteria against metrics.
func evaluateCriteria(criteria []Criterion, m Metrics) bool {
	for _, c := range criteria {
		val := metricValue(c.Metric, m)
		if !compare(val, c.Operator, c.Threshold) {
			return false
		}
	}
	return true
}

// metricValue returns the numeric value of a named metric.
func metricValue(name string, m Metrics) float64 {
	switch name {
	case "waf_uptime_pct":
		return m.WAFUptimePct
	case "log_completeness_pct":
		return m.LogCompletenessPct
	case "dlp_blocks_in_period":
		return float64(m.DLPBlocksInPeriod)
	case "alert_response_time_p95_minutes":
		return m.AlertResponseP95Min
	case "total_requests":
		return float64(m.TotalRequests)
	case "blocked_requests":
		return float64(m.BlockedRequests)
	default:
		return 0
	}
}

// compare evaluates a comparison operation.
func compare(val float64, op string, threshold float64) bool {
	switch op {
	case ">=":
		return val >= threshold
	case "<=":
		return val <= threshold
	case ">":
		return val > threshold
	case "<":
		return val < threshold
	case "==":
		return val == threshold
	default:
		return false
	}
}

// collectEvidence gathers evidence values for a control.
func collectEvidence(c Control, m Metrics) map[string]any {
	ev := make(map[string]any)
	for _, spec := range c.Evidence {
		switch spec.Type {
		case "waf_active":
			ev["waf_operational"] = m.WAFOperational
			ev["waf_uptime_pct"] = m.WAFUptimePct
		case "block_events":
			ev["blocked_requests"] = m.BlockedRequests
			ev["total_requests"] = m.TotalRequests
		case "access_log_entries":
			ev["log_completeness_pct"] = m.LogCompletenessPct
		case "dlp_events":
			ev["dlp_blocks"] = m.DLPBlocksInPeriod
		case "alert_events":
			ev["alert_count"] = m.AlertCount
			ev["alert_response_p95_min"] = m.AlertResponseP95Min
		case "tls_active":
			ev["tls_enabled"] = m.TLSEnabled
		case "rate_limit_active":
			ev["rate_limit_active"] = m.RateLimitActive
		case "ip_acl_active":
			ev["ip_acl_active"] = m.IPACLActive
		}
	}
	return ev
}

// builtinControls returns the built-in compliance control definitions.
func builtinControls() []Control {
	return []Control{
		{
			ID:   "pci_dss_6_4_1",
			Name: "PCI DSS v4.0 Req 6.4.1 — WAF in place",
			Frameworks: []string{FrameworkPCI},
			Evidence: []EvidenceSpec{
				{Type: "waf_active", Description: "WAF is operational and processing requests"},
				{Type: "block_events", Description: "Attack attempts blocked"},
			},
			PassingCriteria: []Criterion{
				{Metric: "waf_uptime_pct", Operator: ">=", Threshold: 99.9},
			},
		},
		{
			ID:   "pci_dss_6_4_2",
			Name: "PCI DSS v4.0 Req 6.4.2 — Attack detection and prevention",
			Frameworks: []string{FrameworkPCI},
			Evidence: []EvidenceSpec{
				{Type: "block_events", Description: "Attacks detected and blocked"},
			},
			PassingCriteria: []Criterion{
				{Metric: "total_requests", Operator: ">", Threshold: 0},
			},
		},
		{
			ID:   "pci_dss_10_2_1",
			Name: "PCI DSS v4.0 Req 10.2.1 — Audit log of individual access",
			Frameworks: []string{FrameworkPCI},
			Evidence: []EvidenceSpec{
				{Type: "access_log_entries", Description: "All requests logged"},
			},
			PassingCriteria: []Criterion{
				{Metric: "log_completeness_pct", Operator: ">=", Threshold: 100},
			},
		},
		{
			ID:   "gdpr_art32",
			Name: "GDPR Art. 32 — Technical security measures",
			Frameworks: []string{FrameworkGDPR},
			Evidence: []EvidenceSpec{
				{Type: "waf_active", Description: "WAF operational"},
				{Type: "block_events", Description: "Attacks blocked"},
				{Type: "dlp_events", Description: "Personal data exfiltration blocked"},
			},
			PassingCriteria: []Criterion{
				{Metric: "waf_uptime_pct", Operator: ">=", Threshold: 99.5},
			},
		},
		{
			ID:   "gdpr_art32_dlp",
			Name: "GDPR Art. 32 — DLP capability active",
			Frameworks: []string{FrameworkGDPR},
			Evidence: []EvidenceSpec{
				{Type: "dlp_events", Description: "DLP blocks present"},
			},
			PassingCriteria: []Criterion{
				{Metric: "dlp_blocks_in_period", Operator: ">=", Threshold: 0},
			},
		},
		{
			ID:   "soc2_cc6_6",
			Name: "SOC 2 CC6.6 — Logical access controls",
			Frameworks: []string{FrameworkSOC2},
			Evidence: []EvidenceSpec{
				{Type: "waf_active", Description: "WAF operational"},
				{Type: "rate_limit_active", Description: "Rate limiting active"},
				{Type: "ip_acl_active", Description: "IP ACL active"},
			},
			PassingCriteria: []Criterion{
				{Metric: "waf_uptime_pct", Operator: ">=", Threshold: 99.5},
			},
		},
		{
			ID:   "soc2_cc7_2",
			Name: "SOC 2 CC7.2 — Security event monitoring",
			Frameworks: []string{FrameworkSOC2},
			Evidence: []EvidenceSpec{
				{Type: "alert_events", Description: "Security alerts generated"},
			},
			PassingCriteria: []Criterion{
				{Metric: "alert_response_time_p95_minutes", Operator: "<=", Threshold: 60},
			},
		},
		{
			ID:   "iso27001_a12_4",
			Name: "ISO 27001 A.12.4 — Logging and monitoring",
			Frameworks: []string{FrameworkISO},
			Evidence: []EvidenceSpec{
				{Type: "access_log_entries", Description: "Request logging active"},
				{Type: "waf_active", Description: "WAF operational"},
			},
			PassingCriteria: []Criterion{
				{Metric: "log_completeness_pct", Operator: ">=", Threshold: 99.0},
			},
		},
		{
			ID:   "iso27001_a14_2",
			Name: "ISO 27001 A.14.2 — Secure development — WAF protection",
			Frameworks: []string{FrameworkISO},
			Evidence: []EvidenceSpec{
				{Type: "block_events", Description: "Web attacks blocked by WAF"},
			},
			PassingCriteria: []Criterion{
				{Metric: "total_requests", Operator: ">", Threshold: 0},
			},
		},
	}
}

// SortedFrameworks returns all known framework identifiers.
func SortedFrameworks() []string {
	fw := []string{FrameworkPCI, FrameworkGDPR, FrameworkSOC2, FrameworkISO}
	sort.Strings(fw)
	return fw
}

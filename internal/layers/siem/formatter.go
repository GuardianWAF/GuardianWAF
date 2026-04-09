// Package siem provides SIEM integration for exporting security events.
package siem

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Format represents the output format for SIEM events.
type Format string

const (
	FormatCEF     Format = "cef"     // Common Event Format
	FormatLEEF    Format = "leef"    // Log Event Extended Format
	FormatJSON    Format = "json"    // Standard JSON
	FormatSyslog  Format = "syslog"  // RFC 5424 Syslog
	FormatSplunk  Format = "splunk"  // Splunk HEC format
	FormatElastic Format = "elastic" // Elasticsearch format
)

// Severity maps internal severity to SIEM severity levels.
type Severity int

const (
	SeverityLow      Severity = 1
	SeverityMedium   Severity = 5
	SeverityHigh     Severity = 8
	SeverityCritical Severity = 10
)

// Event represents a normalized security event for SIEM export.
type Event struct {
	Timestamp   time.Time         `json:"timestamp"`
	EventType   string            `json:"event_type"`
	Severity    Severity          `json:"severity"`
	SourceIP    string            `json:"source_ip"`
	SourcePort  int               `json:"source_port,omitempty"`
	DestIP      string            `json:"dest_ip,omitempty"`
	DestPort    int               `json:"dest_port,omitempty"`
	Method      string            `json:"method,omitempty"`
	Path        string            `json:"path,omitempty"`
	UserAgent   string            `json:"user_agent,omitempty"`
	Host        string            `json:"host,omitempty"`
	RequestID   string            `json:"request_id,omitempty"`
	Action      string            `json:"action"`
	Reason      string            `json:"reason,omitempty"`
	RuleID      string            `json:"rule_id,omitempty"`
	Score       int               `json:"score,omitempty"`
	TenantID    string            `json:"tenant_id,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Fields      map[string]string `json:"fields,omitempty"`
	CountryCode string            `json:"country_code,omitempty"`
	CountryName string            `json:"country_name,omitempty"`
}

// Formatter formats events for SIEM systems.
type Formatter struct {
	format    Format
	hostname  string
	product   string
	version   string
}

// NewFormatter creates a new SIEM event formatter.
func NewFormatter(format Format, hostname, product, version string) *Formatter {
	if hostname == "" {
		hostname = "guardianwaf"
	}
	if product == "" {
		product = "GuardianWAF"
	}
	if version == "" {
		version = "1.0"
	}

	return &Formatter{
		format:   format,
		hostname: hostname,
		product:  product,
		version:  version,
	}
}

// Format formats an event according to the configured format.
func (f *Formatter) Format(event *Event) (string, error) {
	switch f.format {
	case FormatCEF:
		return f.formatCEF(event)
	case FormatLEEF:
		return f.formatLEEF(event)
	case FormatSyslog:
		return f.formatSyslog(event)
	case FormatSplunk:
		return f.formatSplunk(event)
	case FormatElastic:
		return f.formatElastic(event)
	case FormatJSON:
		return f.formatJSON(event)
	default:
		return f.formatJSON(event)
	}
}

// formatCEF formats event as Common Event Format.
func (f *Formatter) formatCEF(event *Event) (string, error) {
	// CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension
	signatureID := event.RuleID
	if signatureID == "" {
		signatureID = event.EventType
	}

	name := event.Reason
	if name == "" {
		name = fmt.Sprintf("WAF %s", event.EventType)
	}

	cef := fmt.Sprintf("CEF:0|GuardianWAF|%s|%s|%s|%s|%d|",
		f.product,
		f.version,
		signatureID,
		name,
		event.Severity,
	)

	// Add extensions
	extensions := []string{
		fmt.Sprintf("rt=%s", formatCEFTimestamp(event.Timestamp)),
		fmt.Sprintf("src=%s", event.SourceIP),
		fmt.Sprintf("cs1=%s", event.Action),
		"cs1Label=action",
	}

	if event.Method != "" {
		extensions = append(extensions, fmt.Sprintf("requestMethod=%s", event.Method))
	}
	if event.Path != "" {
		extensions = append(extensions, fmt.Sprintf("request=%s", event.Path))
	}
	if event.UserAgent != "" {
		extensions = append(extensions, fmt.Sprintf("requestClientApplication=%s", escapeCEF(event.UserAgent)))
	}
	if event.Host != "" {
		extensions = append(extensions, fmt.Sprintf("dhost=%s", event.Host))
	}
	if event.RequestID != "" {
		extensions = append(extensions, fmt.Sprintf("cs2=%s", event.RequestID))
		extensions = append(extensions, "cs2Label=requestId")
	}
	if event.Score > 0 {
		extensions = append(extensions, fmt.Sprintf("cs3=%d", event.Score))
		extensions = append(extensions, "cs3Label=riskScore")
	}
	if event.TenantID != "" {
		extensions = append(extensions, fmt.Sprintf("cs4=%s", event.TenantID))
		extensions = append(extensions, "cs4Label=tenantId")
	}

	return cef + strings.Join(extensions, " "), nil
}

// formatLEEF formats event as Log Event Extended Format.
func (f *Formatter) formatLEEF(event *Event) (string, error) {
	// LEEF:Version|Vendor|Product|Version|EventID|
	leef := fmt.Sprintf("LEEF:2.0|GuardianWAF|%s|%s|%s|",
		f.product,
		f.version,
		event.EventType,
	)

	// Add attributes
	attrs := []string{
		fmt.Sprintf("devTime=%s", formatLEEFTimestamp(event.Timestamp)),
		fmt.Sprintf("src=%s", event.SourceIP),
		fmt.Sprintf("sev=%d", event.Severity),
		fmt.Sprintf("action=%s", event.Action),
	}

	if event.Method != "" {
		attrs = append(attrs, fmt.Sprintf("httpMethod=%s", event.Method))
	}
	if event.Path != "" {
		attrs = append(attrs, fmt.Sprintf("url=%s", event.Path))
	}
	if event.UserAgent != "" {
		attrs = append(attrs, fmt.Sprintf("usrAgent=%s", escapeLEEF(event.UserAgent)))
	}
	if event.Host != "" {
		attrs = append(attrs, fmt.Sprintf("dst=%s", event.Host))
	}
	if event.RequestID != "" {
		attrs = append(attrs, fmt.Sprintf("requestId=%s", event.RequestID))
	}
	if event.Score > 0 {
		attrs = append(attrs, fmt.Sprintf("riskScore=%d", event.Score))
	}
	if event.TenantID != "" {
		attrs = append(attrs, fmt.Sprintf("tenantId=%s", event.TenantID))
	}
	if event.Reason != "" {
		attrs = append(attrs, fmt.Sprintf("reason=%s", escapeLEEF(event.Reason)))
	}

	return leef + strings.Join(attrs, "\t"), nil
}

// formatSyslog formats event as RFC 5424 Syslog.
func (f *Formatter) formatSyslog(event *Event) (string, error) {
	// <priority>version timestamp hostname app-name procid msgid structured-data msg
	priority := 134 // facility=16 (local0), severity=6 (info)
	if event.Severity >= SeverityCritical {
		priority = 136 // severity=0 (emergency)
	} else if event.Severity >= SeverityHigh {
		priority = 132 // severity=3 (error)
	} else if event.Severity >= SeverityMedium {
		priority = 133 // severity=5 (warning)
	}

	timestamp := event.Timestamp.UTC().Format(time.RFC3339)

	msg := fmt.Sprintf("<%d>1 %s %s %s %s - - %s",
		priority,
		timestamp,
		f.hostname,
		f.product,
		f.version,
		formatSyslogMsg(event),
	)

	return msg, nil
}

// formatSplunk formats event for Splunk HEC.
func (f *Formatter) formatSplunk(event *Event) (string, error) {
	// Splunk HEC format
	splunkEvent := map[string]any{
		"time":       event.Timestamp.Unix(),
		"source":     f.product,
		"sourcetype": "guardianwaf",
		"host":       f.hostname,
		"event":      event,
	}

	data, err := json.Marshal(splunkEvent)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// formatElastic formats event for Elasticsearch.
func (f *Formatter) formatElastic(event *Event) (string, error) {
	// Elasticsearch format with index metadata
	index := map[string]any{
		"index": map[string]any{
			"_index": fmt.Sprintf("guardianwaf-%s", event.Timestamp.Format("2006.01.02")),
			"_id":    event.RequestID,
		},
	}

	indexData, err := json.Marshal(index)
	if err != nil {
		return "", err
	}

	eventData, err := json.Marshal(event)
	if err != nil {
		return "", err
	}

	return string(indexData) + "\n" + string(eventData), nil
}

// formatJSON formats event as standard JSON.
func (f *Formatter) formatJSON(event *Event) (string, error) {
	data, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// formatCEFTimestamp formats timestamp for CEF.
func formatCEFTimestamp(t time.Time) string {
	return t.UTC().Format("Jan 02 2006 15:04:05")
}

// formatLEEFTimestamp formats timestamp for LEEF.
func formatLEEFTimestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05")
}

// formatSyslogMsg formats message for syslog.
func formatSyslogMsg(event *Event) string {
	parts := []string{
		fmt.Sprintf("event_type=%s", event.EventType),
		fmt.Sprintf("src_ip=%s", event.SourceIP),
		fmt.Sprintf("action=%s", event.Action),
	}

	if event.Method != "" {
		parts = append(parts, fmt.Sprintf("method=%s", event.Method))
	}
	if event.Path != "" {
		parts = append(parts, fmt.Sprintf("path=%s", event.Path))
	}
	if event.Score > 0 {
		parts = append(parts, fmt.Sprintf("score=%d", event.Score))
	}

	return strings.Join(parts, " ")
}

// escapeCEF escapes special characters in CEF values.
func escapeCEF(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "=", "\\=")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

// escapeLEEF escapes special characters in LEEF values.
func escapeLEEF(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "=", "\\=")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}

package siem

import (
	"fmt"
	"net"
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// EncodeCEF formats a WAF event as a CEF (Common Event Format) line.
// CEF is the de facto standard for SIEM ingestion (ArcSight, Splunk, QRadar).
//
// Format: CEF:Version|Vendor|Product|DevVersion|SignatureID|Name|Severity|Extension
func EncodeCEF(ev engine.Event, vendor, productVersion string) string {
	// Strip port from client IP for the src field.
	src := ev.ClientIP
	if host, _, err := net.SplitHostPort(src); err == nil {
		src = host
	}

	// Determine the action string.
	var act string
	switch ev.Action {
	case engine.ActionBlock:
		act = "blocked"
	case engine.ActionChallenge:
		act = "challenged"
	case engine.ActionLog:
		act = "logged"
	default:
		act = "passed"
	}

	// Build the name field from detector names + finding descriptions.
	var nameParts []string
	for _, f := range ev.Findings {
		if f.Description != "" {
			nameParts = append(nameParts, f.Description)
		} else if f.DetectorName != "" {
			nameParts = append(nameParts, f.DetectorName)
		}
	}
	name := "WAF Event"
	if len(nameParts) > 0 {
		name = strings.Join(nameParts, "; ")
		if len(name) > 200 {
			name = name[:197] + "..."
		}
	}

	severity := cefSeverity(ev.Score)

	// Build the extension (key=value pairs).
	var ext strings.Builder

	// Standard CEF fields.
	ext.WriteString("act=")
	ext.WriteString(escapeCEF(act))
	ext.WriteString(" src=")
	ext.WriteString(escapeCEF(src))
	ext.WriteString(" sproc=")
	ext.WriteString(escapeCEF(ev.Query))
	ext.WriteString(" requestMethod=")
	ext.WriteString(escapeCEF(ev.Method))
	ext.WriteString(" request=")
	ext.WriteString(escapeCEF(ev.Path))
	ext.WriteString(" requestClientApplication=")
	ext.WriteString(escapeCEF(ev.UserAgent))

	// Score.
	fmt.Fprintf(&ext, " cn1=%d", ev.Score)
	ext.WriteString(" cn1Label=WAF_Score")

	// HTTP status code.
	if ev.StatusCode > 0 {
		fmt.Fprintf(&ext, " outcome=%d", ev.StatusCode)
	}

	// Request ID.
	if ev.RequestID != "" {
		ext.WriteString(" suid=")
		ext.WriteString(escapeCEF(ev.RequestID))
	}

	// Host header.
	if ev.Host != "" {
		ext.WriteString(" dhost=")
		ext.WriteString(escapeCEF(ev.Host))
	}

	// Tenant.
	if ev.TenantID != "" {
		ext.WriteString(" cs1=")
		ext.WriteString(escapeCEF(ev.TenantID))
		ext.WriteString(" cs1Label=Tenant")
	}

	// Country code from GeoIP.
	if ev.CountryCode != "" {
		ext.WriteString(" cs2=")
		ext.WriteString(escapeCEF(ev.CountryCode))
		ext.WriteString(" cs2Label=Country")
	}

	// Detector names as a comma-separated list.
	if len(ev.Findings) > 0 {
		var detectors []string
		for _, f := range ev.Findings {
			if f.DetectorName != "" {
				detectors = append(detectors, f.DetectorName)
			}
		}
		if len(detectors) > 0 {
			ext.WriteString(" cs3=")
			ext.WriteString(escapeCEF(strings.Join(detectors, ",")))
			ext.WriteString(" cs3Label=Detectors")
		}
	}

	return fmt.Sprintf(
		"CEF:0|%s|GuardianWAF|%s|%d|%s|%s|%s",
		vendor,
		productVersion,
		ev.Score, // signature ID
		escapeCEF(name),
		severity,
		ext.String(),
	)
}

// escapeCEF escapes a value for inclusion in a CEF line.
// Pipes, backslashes, newlines, and carriage returns are escaped/replaced.
func escapeCEF(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '|':
			b.WriteString(`\|`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteByte(' ')
		case '\r':
			b.WriteByte(' ')
		case '\t':
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// cefSeverity maps a WAF score to a CEF severity string (0–10).
//
//	0–29:   Low (3)
//	30–49:  Medium (3)
//	50–74:  High (6)
//	75–89:  Very High (8)
//	90+:    Critical (10)
func cefSeverity(score int) string {
	switch {
	case score >= 90:
		return "10"
	case score >= 75:
		return "8"
	case score >= 50:
		return "6"
	case score >= 30:
		return "3"
	case score > 0:
		return "3"
	default:
		return "1"
	}
}

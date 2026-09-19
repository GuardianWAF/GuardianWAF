package dashboard

// Regression (bug-hunt round 2026-09-18-r4): writeEventsCSV wrapped the two
// free-text columns (user_agent, findings) in literal Sprintf quotes on top
// of escapeCSV's own quoting. Any value containing a comma, quote, or newline
// made escapeCSV emit a quoted field, which the format string wrapped AGAIN:
// a User-Agent "Mozilla, compatible" was exported as ""Mozilla, compatible"",
// and an RFC-4180 parser reads that back as the literal string
// "Mozilla, compatible" — with spurious quotes. Every such row in every
// evidence export (incidents routinely contain commas in findings
// descriptions) was corrupted; the CSV stayed structurally parseable, so the
// corruption was silent.
//
// The fix lets escapeCSV own quoting entirely: the format string no longer
// pre-wraps the escaped columns, so plain values stay bare and special
// values get exactly one RFC-4180 quoted wrapper and round-trip faithfully.
//
// The harness drives the real production serializer (writeEventsCSV — the
// exact function handleExportEvents delegates to) and parses the output with
// encoding/csv, the same parser class consumers use. The plain control row
// round-trips before AND after the fix, proving the harness itself is sound.

import (
	"encoding/csv"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestWriteEventsCSV_RoundTripsFreeTextFields(t *testing.T) {
	evts := []engine.Event{
		// Control: plain values — must round-trip before AND after the fix.
		{
			ID:        "evt-plain",
			Timestamp: time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC),
			ClientIP:  "203.0.113.7",
			Method:    "GET",
			Path:      "/plain",
			Action:    engine.ActionBlock,
			Score:     75,
			UserAgent: "Chrome/120.0",
		},
		// Defect case: comma-bearing User-Agent.
		{
			ID:        "evt-comma-ua",
			Timestamp: time.Date(2026, 9, 18, 12, 1, 0, 0, time.UTC),
			ClientIP:  "203.0.113.8",
			Method:    "GET",
			Path:      "/comma",
			Action:    engine.ActionBlock,
			Score:     80,
			UserAgent: "Mozilla, compatible",
		},
		// Defect case: findings with comma and double quotes.
		{
			ID:        "evt-comma-findings",
			Timestamp: time.Date(2026, 9, 18, 12, 2, 0, 0, time.UTC),
			ClientIP:  "203.0.113.9",
			Method:    "POST",
			Path:      "/login",
			Action:    engine.ActionBlock,
			Score:     90,
			UserAgent: "bot/1.0",
			Findings: []engine.Finding{
				{DetectorName: "sqli", Description: `match: ' OR 1=1, "delay"(5)`},
			},
		},
	}

	d := &Dashboard{}
	rr := httptest.NewRecorder()
	d.writeEventsCSV(rr, evts)

	records, err := csv.NewReader(strings.NewReader(rr.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("FAIL: exported CSV is not parseable: %v\n%s", err, rr.Body.String())
	}
	if len(records) != 1+len(evts) {
		t.Fatalf("FAIL: expected header + %d rows, got %d records", len(evts), len(records))
	}

	for i, evt := range evts {
		row := records[1+i]
		gotUA := row[7]
		gotFindings := row[8]
		if gotUA != evt.UserAgent {
			t.Errorf("FAIL: row %d (%s) user_agent corrupted by double-wrapped quoting: parsed %q, want %q", i, evt.ID, gotUA, evt.UserAgent)
		}
		wantFindings := ""
		for j, f := range evt.Findings {
			if j > 0 {
				wantFindings += "; "
			}
			wantFindings += f.DetectorName + ":" + f.Description
		}
		if gotFindings != wantFindings {
			t.Errorf("FAIL: row %d (%s) findings corrupted by double-wrapped quoting: parsed %q, want %q", i, evt.ID, gotFindings, wantFindings)
		}
	}
}

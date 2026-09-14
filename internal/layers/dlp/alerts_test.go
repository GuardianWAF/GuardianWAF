package dlp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// The layer's alert history is the store behind the dashboard's and the MCP
// tool's DLP alert surfaces: bounded, filtered, copy-safe, and masked — the
// raw matched value must never leave the scan path.

func newAlertsTestLayer(t *testing.T) *Layer {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ScanRequest = true
	cfg.BlockOnMatch = true
	cfg.Patterns = []string{"credit_card"}
	return NewLayer(cfg)
}

func processWithBody(t *testing.T, l *Layer, body string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/checkout", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	l.Process(&engine.RequestContext{Request: req, Path: "/checkout"})
}

func TestGetAlertsFilterLimitCopyAndMasking(t *testing.T) {
	l := newAlertsTestLayer(t)
	first, second := "4111111111111111", "5555555555554444"
	processWithBody(t, l, `{"card":"`+first+`"}`)
	processWithBody(t, l, `{"card":"`+second+`"}`)

	all := l.GetAlerts(0, "")
	if len(all) != 2 {
		t.Fatalf("FAIL: got %d alerts, want 2 (one per detected request)", len(all))
	}
	for _, a := range all {
		if a.PatternType != "credit_card" {
			t.Fatalf("FAIL: alert %s pattern_type = %q", a.ID, a.PatternType)
		}
		if a.Action != "block" {
			t.Fatalf("FAIL: alert %s action = %q, want block", a.ID, a.Action)
		}
		if a.Path != "/checkout" {
			t.Fatalf("FAIL: alert %s path = %q", a.ID, a.Path)
		}
		if a.ID == "" || a.Timestamp <= 0 {
			t.Fatalf("FAIL: alert %s has an empty id or non-positive timestamp", a.ID)
		}
		if a.MatchedValue == "" {
			t.Fatalf("FAIL: alert %s has an empty masked value", a.ID)
		}
		if strings.Contains(a.MatchedValue, first) || strings.Contains(a.MatchedValue, second) {
			t.Fatalf("FAIL: alert %s carries the raw matched value: %q", a.ID, a.MatchedValue)
		}
	}

	// Pattern-type filter: unknown types return nothing without error.
	if got := l.GetAlerts(0, "nope"); len(got) != 0 {
		t.Fatalf("FAIL: unknown-type filter returned %d alerts, want 0", len(got))
	}

	// Tail limit returns the newest record (monotonic per-layer IDs).
	limited := l.GetAlerts(1, "")
	if len(limited) != 1 || limited[0].ID != all[1].ID {
		t.Fatalf("FAIL: limit=1 returned %+v, want the newest alert %s", limited, all[1].ID)
	}

	// Copy semantics: mutating the returned slice must not affect the store.
	all[0].PatternType = "mutated"
	if again := l.GetAlerts(0, ""); again[0].PatternType == "mutated" {
		t.Fatal("FAIL: GetAlerts leaked internal state")
	}
}

func TestAlertHistoryBounded(t *testing.T) {
	l := newAlertsTestLayer(t)
	matches := []Match{{Type: PatternType("credit_card"), Masked: "****"}}
	for i := 0; i < maxAlerts+50; i++ {
		l.recordAlerts(matches, "block", "", "")
	}
	if got := l.GetAlerts(0, ""); len(got) != maxAlerts {
		t.Fatalf("FAIL: history holds %d alerts, want bounded %d", len(got), maxAlerts)
	}
}

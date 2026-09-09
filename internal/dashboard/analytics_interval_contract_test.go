package dashboard

// Regression: analyticsSeries only honored "day" with a hardcoded hourly
//
// Defect: analyticsSeries supports only "day" and a hardcoded hourly
// else-branch, so the trends/timeseries endpoints accept interval=minute,
// echo it back in the response, and silently return hourly buckets.
// handleAnalyticsTrends compounds the lie: it never passes the interval
// parameter at all while echoing it. Attack-forensics charts are labeled
// by an interval they do not honor.

import (
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestAnalyticsSeriesHonorsMinuteInterval(t *testing.T) {
	base := time.Date(2026, 9, 9, 10, 30, 0, 0, time.UTC)
	evts := []engine.Event{
		{Timestamp: base},
		{Timestamp: base.Add(30 * time.Second)}, // same minute bucket (10:30:30)
	}

	points := analyticsSeries(evts, "minute")

	// Both events land in the same minute (10:30), so an honest
	// minute-bucketed series returns exactly one point at 10:30 — and
	// critically, its key must carry minute granularity, not the hour
	// truncation the else-branch applies today.
	if len(points) != 1 {
		t.Fatalf("FAIL: analyticsSeries(evts, \"minute\") returned %d points (%v) — only \"day\" is honored and everything else falls into the hardcoded hourly else-branch, so minute-granularity requests silently receive hourly buckets", len(points), points)
	}
	if got := points[0]["key"].(string); got != "2026-09-09T10:30:00Z" {
		t.Fatalf("FAIL: minute-series key is %q — the bucket key lacks minute granularity (hourly truncation), so charts labeled interval=minute are actually hourly", got)
	}
}

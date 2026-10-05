package dashboard

import (
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestAnalyticsSeriesChronologicalOrder(t *testing.T) {
	base := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	for _, interval := range []string{"minute", "hour", "day", "unknown"} {
		step := time.Hour
		switch interval {
		case "minute":
			step = time.Minute
		case "day":
			step = 24 * time.Hour
		}
		evts := []engine.Event{{Timestamp: base.Add(2 * step)}, {Timestamp: base.Add(step)}, {Timestamp: base}, {Timestamp: base.Add(step)}, {Timestamp: base.Add(2 * step)}, {Timestamp: base.Add(2 * step)}}
		rows := analyticsSeries(evts, interval)
		if len(rows) != 3 {
			t.Fatalf("%s: got %v", interval, rows)
		}
		for i, row := range rows {
			parsed, err := time.Parse(time.RFC3339, row["key"].(string))
			expected := base.Add(time.Duration(i) * step)
			if interval == "day" {
				expected = time.Date(expected.Year(), expected.Month(), expected.Day(), 0, 0, 0, 0, time.UTC)
			}
			if err != nil || !parsed.Equal(expected) || row["count"] != i+1 {
				t.Fatalf("%s: row %d = %v", interval, i, row)
			}
		}
	}
	// RFC3339 text order differs from chronological order across offsets.
	early := time.Date(2026, 10, 1, 11, 0, 0, 0, time.FixedZone("east", 2*3600))
	rows := analyticsSeries([]engine.Event{{Timestamp: early}, {Timestamp: base}}, "hour")
	if rows[0]["key"] != early.Format(time.RFC3339) {
		t.Fatal("offsets sorted lexically instead of chronologically")
	}
	if len(analyticsSeries(nil, "hour")) != 0 {
		t.Fatal("empty series")
	}
	ranked := countMapToRows(map[string]int{"first": 1, "second": 2}, 10)
	if ranked[0]["key"] != "second" {
		t.Fatal("ranked lists changed")
	}
}

package dashboard

import (
	"encoding/csv"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestWriteEventsCSVMetadataRoundTrip(t *testing.T) {
	for _, value := range []string{"plain", "part,one", `part"one`, "part\none", ""} {
		evt := engine.Event{ID: value, ClientIP: value, Method: value, Path: "/ordinary", UserAgent: "ordinary"}
		rr := httptest.NewRecorder()
		(&Dashboard{}).writeEventsCSV(rr, []engine.Event{evt})
		rows, err := csv.NewReader(strings.NewReader(rr.Body.String())).ReadAll()
		if err != nil || len(rows) != 2 {
			t.Fatalf("%q: rows=%v err=%v", value, rows, err)
		}
		if len(rows[1]) != 9 || rows[1][1] != value || rows[1][2] != value || rows[1][3] != value {
			t.Fatalf("%q: metadata changed: %v", value, rows)
		}
		if rr.Header().Get("Content-Type") != "text/csv" {
			t.Fatal("export content type changed")
		}
	}
	rr := httptest.NewRecorder()
	(&Dashboard{}).writeEventsCSV(rr, nil)
	rows, err := csv.NewReader(strings.NewReader(rr.Body.String())).ReadAll()
	if err != nil || len(rows) != 1 || len(rows[0]) != 9 {
		t.Fatal("empty export/header changed")
	}
}

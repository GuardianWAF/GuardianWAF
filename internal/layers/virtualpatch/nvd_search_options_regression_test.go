package virtualpatch

// Regression (round 2026-09-24-s3r2-cleanup): SearchOptions.ModStartDate/
// ModEndDate/CWEID were declared on the struct but never wired into the NVD
// query — silently ignored by SearchWithContext, and no caller or test ever
// set them. The NVD 2.0 API supports lastModStartDate/lastModEndDate (paired,
// <=120 days) and cweId on cves/2.0, so the fields are now wired; this test
// pins the wiring via the same fake-server query capture the pagination
// regression uses.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestSearchOptionsWiredIntoQuery(t *testing.T) {
	var mu sync.Mutex
	var got map[string][]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.URL.Query()
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(NVDResponse{
			ResultsPerPage:  20,
			StartIndex:      0,
			TotalResults:    0,
			Vulnerabilities: []NVDCVEItem{},
		})
	}))
	defer srv.Close()

	client := NewNVDClient("")
	client.allowPrivate = true
	client.baseURL = srv.URL

	modStart := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	modEnd := modStart.Add(24 * time.Hour)
	_, err := client.SearchWithContext(context.Background(), SearchOptions{
		ModStartDate: modStart,
		ModEndDate:   modEnd,
		CWEID:        "CWE-89",
	})
	if err != nil {
		t.Fatalf("SearchWithContext: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotQ := got["lastModStartDate"]; len(gotQ) != 1 || gotQ[0] != modStart.Format(time.RFC3339) {
		t.Fatalf("FAIL: lastModStartDate not wired into the NVD query: %v", got["lastModStartDate"])
	}
	if gotQ := got["lastModEndDate"]; len(gotQ) != 1 || gotQ[0] != modEnd.Format(time.RFC3339) {
		t.Fatalf("FAIL: lastModEndDate not wired into the NVD query: %v", got["lastModEndDate"])
	}
	if gotQ := got["cweId"]; len(gotQ) != 1 || gotQ[0] != "CWE-89" {
		t.Fatalf("FAIL: cweId not wired into the NVD query: %v", got["cweId"])
	}
}

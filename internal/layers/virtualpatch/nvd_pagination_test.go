package virtualpatch

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
)

// Regression tests (round 88): runUpdate fetched only the FIRST page of NVD
// results (ResultsPerPage: 20, no StartIndex) and never consulted
// resp.TotalResults, so when a 7-day HIGH-severity result set exceeded one
// page every later CVE was silently dropped from the virtual-patch database.
// runUpdate must paginate: advance StartIndex until all of totalResults are
// fetched (bounded by a safety page cap), honoring context cancellation.

// fakeNVDCVEs builds n distinct HIGH-severity CVE items.
func fakeNVDCVEs(n int) []NVDCVEItem {
	items := make([]NVDCVEItem, 0, n)
	for i := 1; i <= n; i++ {
		id := fmt.Sprintf("CVE-2025-%04d", i)
		items = append(items, NVDCVEItem{CVE: NVDCVE{
			ID: id,
			Descriptions: []NVDDescription{
				{Lang: "en", Value: "High severity test vulnerability " + id},
			},
			Metrics: NVDMetrics{
				CVSSMetricV31: []NVDCVSSMetricV31{{
					CVSSData: NVDCVSSData{BaseScore: 9.8, BaseSeverity: "HIGH"},
				}},
			},
			Published:    "2025-01-01T00:00:00.000",
			LastModified: "2025-01-01T00:00:00.000",
		}})
	}
	return items
}

func TestRunUpdatePaginatesAllPages(t *testing.T) {
	const total = 25 // two pages at runUpdate's ResultsPerPage: 20
	items := fakeNVDCVEs(total)

	var mu sync.Mutex
	var startIndexes []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		start, _ := strconv.Atoi(q.Get("startIndex"))
		perPage, _ := strconv.Atoi(q.Get("resultsPerPage"))
		if perPage <= 0 {
			perPage = 20
		}
		mu.Lock()
		startIndexes = append(startIndexes, start)
		mu.Unlock()

		end := start + perPage
		if end > len(items) {
			end = len(items)
		}
		_ = json.NewEncoder(w).Encode(NVDResponse{
			ResultsPerPage:  perPage,
			StartIndex:      start,
			TotalResults:    len(items),
			Vulnerabilities: items[start:end],
		})
	}))
	defer srv.Close()

	client := NewNVDClient("")
	client.allowPrivate = true
	client.baseURL = srv.URL // bypass private IP validation for the test server

	layer := NewLayer(&Config{Enabled: true, AutoGenerateRules: false})
	layer.nvdClient = client

	// loadDefaultPatches seeds the database at construction — assert growth
	// relative to that baseline.
	before := layer.database.Stats().TotalCVEs

	layer.runUpdate(context.Background())

	// The last-page CVE must be in the database — pre-fix it was dropped.
	if entry := layer.database.GetCVE("CVE-2025-0025"); entry == nil {
		t.Fatalf("FAIL: last-page CVE CVE-2025-0025 missing from the CVE database — runUpdate fetched only the first page")
	}
	if got := layer.database.Stats().TotalCVEs; got != before+total {
		t.Fatalf("FAIL: expected %d CVEs after pagination (baseline %d + %d fetched), got %d", before+total, before, total, got)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(startIndexes) != 2 || startIndexes[0] != 0 || startIndexes[1] != 20 {
		t.Fatalf("FAIL: expected two paginated requests with startIndex [0 20], got %v", startIndexes)
	}
}

func TestRunUpdateEmptyResultSet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	layer := NewLayer(&Config{Enabled: true, AutoGenerateRules: false})
	layer.nvdClient = client

	before := layer.database.Stats().TotalCVEs
	layer.runUpdate(context.Background())

	if got := layer.database.Stats().TotalCVEs; got != before {
		t.Fatalf("FAIL: empty result set changed the CVE count: %d -> %d", before, got)
	}
}

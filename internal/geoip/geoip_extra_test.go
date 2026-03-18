package geoip

import (
	"bytes"
	"compress/gzip"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadCSV_EmptyLines(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	os.WriteFile(csv, []byte(`
# comment
1.0.0.0,1.0.0.255,AU

invalid-line
short

8.8.8.0,8.8.8.255,US
`), 0644)

	db, err := LoadCSV(csv)
	if err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}
	if db.Count() != 2 {
		t.Errorf("expected 2 valid ranges, got %d", db.Count())
	}
}

func TestLoadCSV_InvalidIPs(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	os.WriteFile(csv, []byte(`notanip,alsonotanip,XX
1.0.0.0,1.0.0.255,AU
bad,1.0.0.255,US
1.0.0.0,bad,US
1.0.0.0,1.0.0.255,TOOLONG
`), 0644)

	db, err := LoadCSV(csv)
	if err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}
	// Only the valid AU line should be loaded
	if db.Count() != 1 {
		t.Errorf("expected 1 valid range, got %d", db.Count())
	}
}

func TestLoadCSV_InvalidCIDR(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	os.WriteFile(csv, []byte(`not-a-cidr,US
10.0.0.0/8,TR
300.0.0.0/8,XX
`), 0644)

	db, err := LoadCSV(csv)
	if err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}
	if db.Count() != 1 {
		t.Errorf("expected 1 valid range, got %d", db.Count())
	}
}

func TestCount_NilDB(t *testing.T) {
	var db *DB
	if db.Count() != 0 {
		t.Error("expected 0 for nil DB")
	}
}

func TestCountryName_Lowercase(t *testing.T) {
	if name := CountryName("us"); name != "United States" {
		t.Errorf("expected 'United States' for lowercase, got %q", name)
	}
	if name := CountryName("tr"); name != "Turkey" {
		t.Errorf("expected 'Turkey' for lowercase, got %q", name)
	}
}

func TestLookup_BoundaryIPs(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	os.WriteFile(csv, []byte(`10.0.0.0,10.0.0.255,US
10.0.1.0,10.0.1.255,TR
`), 0644)

	db, err := LoadCSV(csv)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		ip       string
		expected string
	}{
		{"10.0.0.0", "US"},   // start of first range
		{"10.0.0.255", "US"}, // end of first range
		{"10.0.1.0", "TR"},   // start of second range
		{"10.0.1.255", "TR"}, // end of second range
		{"9.255.255.255", ""}, // just before range
		{"10.0.2.0", ""},      // just after range
	}
	for _, tt := range tests {
		got := db.Lookup(net.ParseIP(tt.ip))
		if got != tt.expected {
			t.Errorf("Lookup(%s) = %q, want %q", tt.ip, got, tt.expected)
		}
	}
}

func TestLoadOrDownload_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	os.WriteFile(csv, []byte(`1.0.0.0,1.0.0.255,AU
`), 0644)

	db, err := LoadOrDownload(csv, "", 0)
	if err != nil {
		t.Fatalf("LoadOrDownload: %v", err)
	}
	if db.Count() != 1 {
		t.Errorf("expected 1, got %d", db.Count())
	}
}

func TestLoadOrDownload_EmptyPath(t *testing.T) {
	// With empty path, it tries "geoip.csv" which probably doesn't exist
	// and would try to download — but with a bad URL it should fail
	_, err := LoadOrDownload("", "http://127.0.0.1:1/nonexistent.csv.gz", 0)
	if err == nil {
		t.Error("expected error for unreachable download URL")
	}
}

func TestCidrToRange_IPv6(t *testing.T) {
	_, _, err := cidrToRange("::1/128")
	if err == nil {
		t.Error("expected error for IPv6 CIDR")
	}
}

func TestCidrToRange_Valid(t *testing.T) {
	start, end, err := cidrToRange("192.168.1.0/24")
	if err != nil {
		t.Fatalf("cidrToRange: %v", err)
	}
	expectedStart := ipToUint32(net.ParseIP("192.168.1.0"))
	expectedEnd := ipToUint32(net.ParseIP("192.168.1.255"))
	if start != expectedStart {
		t.Errorf("start: got %d, want %d", start, expectedStart)
	}
	if end != expectedEnd {
		t.Errorf("end: got %d, want %d", end, expectedEnd)
	}
}

func TestIpToUint32_NilIP(t *testing.T) {
	result := ipToUint32(nil)
	if result != 0 {
		t.Errorf("expected 0 for nil, got %d", result)
	}
}

func TestDownloadDB_MockServer(t *testing.T) {
	// Serve a plain CSV (not gzipped)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("1.0.0.0,1.0.0.255,AU\n8.8.8.0,8.8.8.255,US\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	csvPath := filepath.Join(dir, "downloaded.csv")

	err := downloadDB(srv.URL+"/geoip.csv", csvPath)
	if err != nil {
		t.Fatalf("downloadDB: %v", err)
	}

	db, err := LoadCSV(csvPath)
	if err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}
	if db.Count() != 2 {
		t.Errorf("expected 2, got %d", db.Count())
	}
}

func TestDownloadDB_MockServerGzipped(t *testing.T) {
	// Serve a gzipped CSV
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte("10.0.0.0,10.0.0.255,TR\n"))
	gz.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.WriteHeader(200)
		w.Write(buf.Bytes())
	}))
	defer srv.Close()

	dir := t.TempDir()
	csvPath := filepath.Join(dir, "downloaded.csv")

	// URL doesn't end with .gz but Content-Type has gzip
	err := downloadDB(srv.URL+"/geoip.csv", csvPath)
	if err != nil {
		t.Fatalf("downloadDB: %v", err)
	}

	db, err := LoadCSV(csvPath)
	if err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}
	if db.Count() != 1 {
		t.Errorf("expected 1, got %d", db.Count())
	}
	if got := db.Lookup(net.ParseIP("10.0.0.1")); got != "TR" {
		t.Errorf("expected TR, got %q", got)
	}
}

func TestDownloadDB_GzURL(t *testing.T) {
	// Serve gzipped content via .gz URL
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte("192.168.0.0/16,DE\n"))
	gz.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(buf.Bytes())
	}))
	defer srv.Close()

	dir := t.TempDir()
	csvPath := filepath.Join(dir, "geo.csv")

	err := downloadDB(srv.URL+"/file.csv.gz", csvPath)
	if err != nil {
		t.Fatalf("downloadDB: %v", err)
	}

	db, err := LoadCSV(csvPath)
	if err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}
	if db.Count() != 1 {
		t.Errorf("expected 1, got %d", db.Count())
	}
}

func TestDownloadDB_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	dir := t.TempDir()
	err := downloadDB(srv.URL+"/missing", filepath.Join(dir, "geo.csv"))
	if err == nil {
		t.Error("expected error for 404")
	}
}

func TestLoadOrDownload_FreshFile(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	os.WriteFile(csv, []byte("1.0.0.0,1.0.0.255,AU\n"), 0644)

	// maxAge > 0 and file is fresh
	db, err := LoadOrDownload(csv, "", 24*time.Hour)
	if err != nil {
		t.Fatalf("LoadOrDownload: %v", err)
	}
	if db.Count() != 1 {
		t.Errorf("expected 1, got %d", db.Count())
	}
}

func TestLoadOrDownload_DownloadWithMock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("8.8.8.0,8.8.8.255,US\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	// File doesn't exist, should download
	db, err := LoadOrDownload(csv, srv.URL+"/geo.csv", 0)
	if err != nil {
		t.Fatalf("LoadOrDownload: %v", err)
	}
	if db.Count() != 1 {
		t.Errorf("expected 1, got %d", db.Count())
	}
}

func TestLoadCSV_ExtraFieldsFormat(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	// Format with extra columns (like MaxMind)
	os.WriteFile(csv, []byte(`1.0.0.0,1.0.0.255,AU,extra1,extra2
8.8.8.0,8.8.8.255,US,extra
`), 0644)

	db, err := LoadCSV(csv)
	if err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}
	if db.Count() != 2 {
		t.Errorf("expected 2, got %d", db.Count())
	}
	if got := db.Lookup(net.ParseIP("1.0.0.1")); got != "AU" {
		t.Errorf("expected AU, got %q", got)
	}
}

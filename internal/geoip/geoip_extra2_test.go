package geoip

import (
	"bytes"
	"compress/gzip"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadCSV_ScannerError(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	// Write a line longer than bufio.Scanner's default 64KB token limit
	longLine := strings.Repeat("a", 70000)
	_ = os.WriteFile(csv, []byte(longLine), 0o644)

	_, err := LoadCSV(csv)
	if err == nil {
		t.Error("expected scanner error for oversized line")
	}
}

func TestGeoIPDownloadLimitReaderRejectsTrailingOversize(t *testing.T) {
	reader := limitGeoIPDownloadReader(strings.NewReader("abcdef"), 3)
	data, err := io.ReadAll(reader)
	if err == nil {
		t.Fatal("expected oversized GeoIP download to be rejected")
	}
	if string(data) != "abc" {
		t.Fatalf("read data = %q, want first bounded bytes", data)
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized download rejected with unexpected error: %v", err)
	}
}

func TestCleanGeoIPFilePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		path       string
		allowEmpty bool
		want       string
		wantErr    bool
	}{
		{name: "relative", path: filepath.Join("data", "..", "geo.csv"), want: "geo.csv"},
		{name: "empty allowed", allowEmpty: true, want: ""},
		{name: "empty rejected", wantErr: true},
		{name: "nul rejected", path: "geo\x00.csv", wantErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := cleanGeoIPFilePath(tt.path, tt.allowEmpty)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("cleanGeoIPFilePath: %v", err)
			}
			if got != tt.want {
				t.Fatalf("cleanGeoIPFilePath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadCSVRejectsNULPath(t *testing.T) {
	t.Parallel()

	if _, err := LoadCSV("geo\x00.csv"); err == nil {
		t.Fatal("expected NUL path error")
	}
}

func TestLoadOrDownloadRejectsNULPath(t *testing.T) {
	t.Parallel()

	if _, err := LoadOrDownload("geo\x00.csv", "http://127.0.0.1:1/geo.csv", 0); err == nil {
		t.Fatal("expected NUL path error")
	}
}

func TestDownloadDBRejectsNULPathBeforeRequest(t *testing.T) {
	t.Parallel()

	var requested bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("1.0.0.0,1.0.0.255,AU\n"))
	}))
	defer srv.Close()

	if err := downloadDB(srv.URL+"/geo.csv", "geo\x00.csv"); err == nil {
		t.Fatal("expected NUL path error")
	}
	if requested {
		t.Fatal("downloadDB should reject path before making HTTP request")
	}
}

func TestStartAutoRefreshRejectsNULPath(t *testing.T) {
	db := New()
	var requested bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("1.0.0.0,1.0.0.255,AU\n"))
	}))
	defer srv.Close()

	stop := db.StartAutoRefresh("geo\x00.csv", srv.URL+"/geo.csv", time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	stop()

	if requested {
		t.Fatal("auto-refresh should reject invalid path before download")
	}
	if db.Count() != 0 {
		t.Fatalf("auto-refresh loaded data despite invalid path: %d ranges", db.Count())
	}
}

// TestLoadOrDownload_EmptyDownloadURL pins the empty-downloadURL branch, which
// falls back to autoDownloadURL(). It must stay hermetic: the earlier version of
// this test let the fallback reach the real download.db-ip.com host and asserted
// nothing ("either outcome is acceptable"), so on a networked machine it pulled
// the live ~31MB country database into the test path. That is how a GeoIP dump
// once ended up committed under internal/geoip/. Assert the URL the fallback
// builds instead of fetching it, then exercise the download path against a
// local server.
func TestLoadOrDownload_EmptyDownloadURL(t *testing.T) {
	auto := autoDownloadURL()
	if !strings.HasPrefix(auto, "https://download.db-ip.com/free/dbip-country-lite-") {
		t.Fatalf("autoDownloadURL() = %q, want the DB-IP Lite endpoint", auto)
	}
	if !strings.HasSuffix(auto, ".csv.gz") {
		t.Fatalf("autoDownloadURL() = %q, want a .csv.gz suffix", auto)
	}

	// Exercise the real download+load path against a local gzip server so the
	// branch is covered without any outbound network traffic.
	var body bytes.Buffer
	gz := gzip.NewWriter(&body)
	if _, err := gz.Write([]byte("8.8.8.0,8.8.8.255,US\n")); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(body.Bytes())
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "geo-test-auto.csv")
	db, err := LoadOrDownload(path, srv.URL+"/dbip-country-lite.csv.gz", 0)
	if err != nil {
		t.Fatalf("LoadOrDownload: %v", err)
	}
	if db.Count() != 1 {
		t.Fatalf("db.Count() = %d, want 1", db.Count())
	}
	if got := db.Lookup(net.ParseIP("8.8.8.8")); got != "US" {
		t.Fatalf("Lookup(8.8.8.8) = %q, want US", got)
	}
}

func TestLoadOrDownload_StaleFile_Fallback(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	_ = os.WriteFile(csv, []byte("1.0.0.0,1.0.0.255,AU\n"), 0o644)

	// Make file genuinely stale
	oldTime := time.Now().Add(-48 * time.Hour)
	_ = os.Chtimes(csv, oldTime, oldTime)

	// Bad download URL should fall back to existing stale file
	db, err := LoadOrDownload(csv, "http://127.0.0.1:1/fail.csv", 24*time.Hour)
	if err != nil {
		t.Fatalf("expected fallback to old file, got: %v", err)
	}
	if db.Count() != 1 {
		t.Errorf("expected 1 from fallback, got %d", db.Count())
	}
}

func TestDownloadDB_BadURLString(t *testing.T) {
	dir := t.TempDir()
	err := downloadDB("http://\x00invalid", filepath.Join(dir, "geo.csv"))
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestDownloadDB_MkdirAllError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("1.0.0.0,1.0.0.255,AU\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	parentFile := filepath.Join(dir, "parent")
	_ = os.WriteFile(parentFile, []byte("x"), 0o644)

	err := downloadDB(srv.URL+"/geo.csv", filepath.Join(parentFile, "sub", "geo.csv"))
	if err == nil {
		t.Error("expected mkdir error when parent is a file")
	}
}

func TestDownloadDB_CreateError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("1.0.0.0,1.0.0.255,AU\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	targetDir := filepath.Join(dir, "geo.csv")
	_ = os.Mkdir(targetDir, 0o755)

	err := downloadDB(srv.URL+"/geo.csv", targetDir)
	if err == nil {
		t.Error("expected create error when path is an existing directory")
	}
}

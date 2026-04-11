package geoip

import (
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

func TestLoadOrDownload_EmptyDownloadURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geo-test-auto.csv")
	_, err := LoadOrDownload(path, "", 0)
	// Auto-download may succeed (network) or fail (no network).
	// Either is acceptable; just verify no panic.
	if err != nil {
		t.Logf("auto-download failed as expected without network: %v", err)
	} else {
		t.Log("auto-download succeeded")
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

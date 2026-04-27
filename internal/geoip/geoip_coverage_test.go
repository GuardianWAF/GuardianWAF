package geoip

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- Ready ---

func TestReady_NilDB(t *testing.T) {
	var db *DB
	if db.Ready() {
		t.Error("expected false for nil DB")
	}
}

func TestReady_EmptyDB(t *testing.T) {
	db := New()
	if db.Ready() {
		t.Error("expected false for empty DB")
	}
}

func TestReady_WithData(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	_ = os.WriteFile(csv, []byte("1.0.0.0,1.0.0.255,AU\n"), 0o644)

	db, err := LoadCSV(csv)
	if err != nil {
		t.Fatal(err)
	}
	if !db.Ready() {
		t.Error("expected true for DB with data")
	}
}

// --- validateURLNotPrivate ---

func TestValidateURLNotPrivate_LoopbackIP(t *testing.T) {
	err := validateURLNotPrivate("http://127.0.0.1/geoip.csv")
	if err == nil {
		t.Error("expected error for loopback IP")
	}
}

func TestValidateURLNotPrivate_PrivateIP(t *testing.T) {
	err := validateURLNotPrivate("http://192.168.1.1/geoip.csv")
	if err == nil {
		t.Error("expected error for private IP")
	}
}

func TestValidateURLNotPrivate_LinkLocalIP(t *testing.T) {
	err := validateURLNotPrivate("http://169.254.1.1/geoip.csv")
	if err == nil {
		t.Error("expected error for link-local IP")
	}
}

func TestValidateURLNotPrivate_UnspecifiedIP(t *testing.T) {
	err := validateURLNotPrivate("http://0.0.0.0/geoip.csv")
	if err == nil {
		t.Error("expected error for unspecified IP")
	}
}

func TestValidateURLNotPrivate_Localhost(t *testing.T) {
	err := validateURLNotPrivate("http://localhost/geoip.csv")
	if err == nil {
		t.Error("expected error for localhost hostname")
	}
}

func TestValidateURLNotPrivate_InternalSuffix(t *testing.T) {
	err := validateURLNotPrivate("http://myhost.internal/geoip.csv")
	if err == nil {
		t.Error("expected error for .internal hostname")
	}
}

func TestValidateURLNotPrivate_LocalSuffix(t *testing.T) {
	err := validateURLNotPrivate("http://myhost.local/geoip.csv")
	if err == nil {
		t.Error("expected error for .local hostname")
	}
}

func TestValidateURLNotPrivate_PublicIP(t *testing.T) {
	err := validateURLNotPrivate("http://8.8.8.8/geoip.csv")
	if err != nil {
		t.Errorf("expected no error for public IP, got: %v", err)
	}
}

func TestValidateURLNotPrivate_PublicHostname(t *testing.T) {
	// A public hostname should pass (if DNS resolves to a public IP)
	err := validateURLNotPrivate("http://example.com/geoip.csv")
	if err != nil {
		t.Logf("validateURLNotPrivate for example.com returned: %v (may depend on DNS)", err)
	}
}

func TestValidateURLNotPrivate_InvalidURL(t *testing.T) {
	err := validateURLNotPrivate("://invalid")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestValidateURLNotPrivate_IPv6Loopback(t *testing.T) {
	err := validateURLNotPrivate("http://[::1]/geoip.csv")
	if err == nil {
		t.Error("expected error for IPv6 loopback")
	}
}

func TestValidateURLNotPrivate_IPv6Private(t *testing.T) {
	err := validateURLNotPrivate("http://[fd00::1]/geoip.csv")
	if err == nil {
		t.Error("expected error for IPv6 private address")
	}
}

// --- StartAutoRefresh additional paths ---

func TestStartAutoRefresh_WithDownloadFailure(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	_ = os.WriteFile(csv, []byte("1.0.0.0,1.0.0.255,AU\n"), 0o644)

	db, _ := LoadCSV(csv)

	// Use a bad URL that will fail; should not panic
	stop := db.StartAutoRefresh(csv, "http://127.0.0.1:1/nonexistent.csv.gz", 50*time.Millisecond)
	time.Sleep(150 * time.Millisecond)
	stop()
}

func TestStartAutoRefresh_DownloadSuccessButReloadFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("not-valid-csv-data"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	_ = os.WriteFile(csv, []byte("1.0.0.0,1.0.0.255,AU\n"), 0o644)

	db, _ := LoadCSV(csv)
	stop := db.StartAutoRefresh("/nonexistent/path.csv", srv.URL+"/geo.csv", 50*time.Millisecond)
	time.Sleep(150 * time.Millisecond)
	stop()
}

func TestStartAutoRefresh_NegativeInterval(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	_ = os.WriteFile(csv, []byte("1.0.0.0,1.0.0.255,AU\n"), 0o644)

	db, _ := LoadCSV(csv)
	// Negative interval should default to 24h
	stop := db.StartAutoRefresh(csv, "", -1*time.Second)
	// Just verify it starts and stops cleanly
	stop()
}

// --- downloadDB additional paths ---

func TestDownloadDB_WarnOnHTTPURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("1.0.0.0,1.0.0.255,AU\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	// Use the http:// URL (not https) to test the warning path
	err := downloadDB(srv.URL+"/geo.csv", filepath.Join(dir, "geo.csv"))
	if err != nil {
		t.Fatalf("downloadDB: %v", err)
	}
}

func TestDownloadDB_NilBodyRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("1.0.0.0,1.0.0.255,AU\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	err := downloadDB(srv.URL+"/geo.csv", filepath.Join(dir, "geo.csv"))
	if err != nil {
		t.Fatalf("downloadDB: %v", err)
	}
}

func TestDownloadDB_InvalidURL(t *testing.T) {
	dir := t.TempDir()
	err := downloadDB("http://\x00bad", filepath.Join(dir, "geo.csv"))
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestDownloadDB_SSRFProtection(t *testing.T) {
	dir := t.TempDir()
	// Reset test flag to enforce SSRF protection
	origAllow := testAllowPrivate
	testAllowPrivate = false
	defer func() { testAllowPrivate = origAllow }()

	err := downloadDB("http://127.0.0.1:1/geo.csv", filepath.Join(dir, "geo.csv"))
	if err == nil {
		t.Error("expected SSRF protection to reject localhost URL")
	}
}

// --- LoadOrDownload additional edge cases ---

func TestLoadOrDownload_NonexistentNoOldFile(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "nonexistent.csv")

	_, err := LoadOrDownload(csv, "http://127.0.0.1:1/fail.csv", 0)
	if err == nil {
		t.Error("expected error when file doesn't exist and download fails")
	}
}

// --- Reload edge cases ---

func TestReload_ConcurrentLookup(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	_ = os.WriteFile(csv, []byte("10.0.0.0,10.0.0.255,US\n"), 0o644)

	db, _ := LoadCSV(csv)

	// Reload with different data in a goroutine while doing lookups
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			_ = os.WriteFile(csv, []byte("8.8.8.0,8.8.8.255,TR\n"), 0o644)
			_ = db.Reload(csv)
		}
	}()

	for i := 0; i < 100; i++ {
		db.Lookup(net.ParseIP("8.8.8.8"))
	}
	<-done
}

// --- ipToUint32 additional cases ---

func TestIpToUint32_IPv4MappedIPv6(t *testing.T) {
	// IPv4-mapped IPv6 address should produce correct uint32
	ip := net.ParseIP("::ffff:192.168.1.1")
	v4 := ip.To4()
	result := ipToUint32(v4)
	expected := uint32(0xC0A80101)
	if result != expected {
		t.Errorf("expected %d, got %d", expected, result)
	}
}

// --- cidrToRange additional cases ---

func TestCidrToRange_Single32(t *testing.T) {
	start, end, err := cidrToRange("10.0.0.1/32")
	if err != nil {
		t.Fatalf("cidrToRange: %v", err)
	}
	if start != end {
		t.Errorf("expected start==end for /32, got start=%d end=%d", start, end)
	}
}

func TestCidrToRange_Slash0(t *testing.T) {
	start, end, err := cidrToRange("0.0.0.0/0")
	if err != nil {
		t.Fatalf("cidrToRange: %v", err)
	}
	if start != 0 {
		t.Errorf("expected start=0, got %d", start)
	}
	if end != 0xFFFFFFFF {
		t.Errorf("expected end=0xFFFFFFFF, got %d", end)
	}
}

func TestCidrToRange_InvalidCIDR(t *testing.T) {
	_, _, err := cidrToRange("not-a-cidr")
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

// --- LoadCSV edge cases ---

func TestLoadCSV_WhitespaceInFields(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	_ = os.WriteFile(csv, []byte("  1.0.0.0 , 1.0.0.255 , AU  \n"), 0o644)

	db, err := LoadCSV(csv)
	if err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}
	if db.Count() != 1 {
		t.Errorf("expected 1 range, got %d", db.Count())
	}
	got := db.Lookup(net.ParseIP("1.0.0.1"))
	if got != "AU" {
		t.Errorf("expected AU, got %q", got)
	}
}

func TestLoadCSV_CountryCodeUppercased(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	_ = os.WriteFile(csv, []byte("1.0.0.0,1.0.0.255,au\n"), 0o644)

	db, err := LoadCSV(csv)
	if err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}
	got := db.Lookup(net.ParseIP("1.0.0.1"))
	if got != "AU" {
		t.Errorf("expected AU (uppercased), got %q", got)
	}
}

// --- autoDownloadURL ---

func TestAutoDownloadURL(t *testing.T) {
	url := autoDownloadURL()
	if url == "" {
		t.Error("expected non-empty auto download URL")
	}
	// Should contain db-ip.com
	if !containsSubstring(url, "db-ip.com") {
		t.Errorf("expected URL to contain db-ip.com, got %q", url)
	}
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

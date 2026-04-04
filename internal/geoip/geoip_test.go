package geoip

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestNew(t *testing.T) {
	db := New()
	if db.Count() != 0 {
		t.Errorf("expected 0, got %d", db.Count())
	}
}

func TestLookupNilDB(t *testing.T) {
	var db *DB
	if code := db.Lookup(net.ParseIP("1.2.3.4")); code != "" {
		t.Errorf("expected empty, got %q", code)
	}
}

func TestLoadCSVSimpleFormat(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	_ = os.WriteFile(csv, []byte(`# GeoIP test data
1.0.0.0,1.0.0.255,AU
1.0.1.0,1.0.3.255,CN
8.8.8.0,8.8.8.255,US
`), 0o644)

	db, err := LoadCSV(csv)
	if err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}
	if db.Count() != 3 {
		t.Errorf("expected 3 ranges, got %d", db.Count())
	}

	tests := []struct {
		ip       string
		expected string
	}{
		{"1.0.0.1", "AU"},
		{"1.0.0.255", "AU"},
		{"1.0.1.100", "CN"},
		{"8.8.8.8", "US"},
		{"2.2.2.2", ""}, // not in DB
		{"192.168.1.1", ""},
	}
	for _, tt := range tests {
		got := db.Lookup(net.ParseIP(tt.ip))
		if got != tt.expected {
			t.Errorf("Lookup(%s) = %q, want %q", tt.ip, got, tt.expected)
		}
	}
}

func TestLoadCSVCIDRFormat(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	_ = os.WriteFile(csv, []byte(`10.0.0.0/8,US
172.16.0.0/12,DE
192.168.0.0/16,TR
`), 0o644)

	db, err := LoadCSV(csv)
	if err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}
	if db.Count() != 3 {
		t.Errorf("expected 3, got %d", db.Count())
	}

	tests := []struct {
		ip       string
		expected string
	}{
		{"10.0.0.1", "US"},
		{"10.255.255.255", "US"},
		{"172.16.0.1", "DE"},
		{"172.31.255.254", "DE"},
		{"192.168.1.1", "TR"},
		{"192.169.0.1", ""},
	}
	for _, tt := range tests {
		got := db.Lookup(net.ParseIP(tt.ip))
		if got != tt.expected {
			t.Errorf("Lookup(%s) = %q, want %q", tt.ip, got, tt.expected)
		}
	}
}

func TestLookupNilIP(t *testing.T) {
	db := New()
	if code := db.Lookup(nil); code != "" {
		t.Errorf("expected empty for nil IP, got %q", code)
	}
}

func TestLookupIPv6(t *testing.T) {
	db := New()
	// IPv6 not supported, should return ""
	if code := db.Lookup(net.ParseIP("::1")); code != "" {
		t.Errorf("expected empty for IPv6, got %q", code)
	}
}

func TestCountryName(t *testing.T) {
	if name := CountryName("US"); name != "United States" {
		t.Errorf("expected 'United States', got %q", name)
	}
	if name := CountryName("TR"); name != "Turkey" {
		t.Errorf("expected 'Turkey', got %q", name)
	}
	if name := CountryName("XX"); name != "XX" {
		t.Errorf("expected 'XX' for unknown, got %q", name)
	}
}

func TestLoadCSVFileNotFound(t *testing.T) {
	_, err := LoadCSV("/nonexistent/file.csv")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func BenchmarkLookup(b *testing.B) {
	dir := b.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	// Generate 1000 ranges
	var data []byte
	for i := range 1000 {
		hi := i / 256
		lo := i % 256
		data = append(data, []byte(
			net.IPv4(byte(hi), byte(lo), 0, 0).String()+","+
				net.IPv4(byte(hi), byte(lo), 255, 255).String()+",US\n")...)
	}
	_ = os.WriteFile(csv, data, 0o644)

	db, _ := LoadCSV(csv)
	ip := net.ParseIP("1.100.50.25")

	b.ResetTimer()
	for range b.N {
		db.Lookup(ip)
	}
}

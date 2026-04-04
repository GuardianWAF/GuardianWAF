// Package geoip provides IP-to-country lookup using a CSV database.
// Zero external dependencies — uses binary search on sorted IP ranges.
// Supports MaxMind GeoLite2 CSV format or simple start_ip,end_ip,country CSV.
package geoip

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DB is a GeoIP database that maps IP addresses to country codes.
type DB struct {
	mu     sync.RWMutex
	ranges []ipRange
}

type ipRange struct {
	start   uint32
	end     uint32
	country string // ISO 3166-1 alpha-2 (e.g., "US", "CN", "TR")
}

// New creates an empty GeoIP database.
func New() *DB {
	return &DB{}
}

// LoadCSV loads a GeoIP database from a CSV file.
// Supported formats:
//   - start_ip,end_ip,country_code (simple)
//   - CIDR,country_code (CIDR format)
//   - Lines starting with # are ignored (comments)
func LoadCSV(path string) (*DB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening geoip db: %w", err)
	}
	defer f.Close()

	db := &DB{}
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || line[0] == '#' {
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}

		// Trim whitespace from all parts
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}

		if len(parts) == 2 {
			// Format: CIDR,country
			cidr := parts[0]
			country := strings.ToUpper(parts[1])
			start, end, err := cidrToRange(cidr)
			if err != nil {
				continue // skip invalid
			}
			db.ranges = append(db.ranges, ipRange{start: start, end: end, country: country})
		} else if len(parts) >= 3 {
			// Format: start_ip,end_ip,country (or with extra fields)
			startIP := net.ParseIP(parts[0])
			endIP := net.ParseIP(parts[1])
			country := strings.ToUpper(parts[2])
			if startIP == nil || endIP == nil || len(country) != 2 {
				continue
			}
			db.ranges = append(db.ranges, ipRange{
				start:   ipToUint32(startIP),
				end:     ipToUint32(endIP),
				country: country,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading geoip db: %w", err)
	}

	// Sort by start IP for binary search
	sort.Slice(db.ranges, func(i, j int) bool {
		return db.ranges[i].start < db.ranges[j].start
	})

	return db, nil
}

// Lookup returns the country code for the given IP address.
// Returns "" if not found or IP is nil/IPv6.
func (db *DB) Lookup(ip net.IP) string {
	if db == nil || ip == nil {
		return ""
	}

	// Only IPv4 supported for now
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}

	target := ipToUint32(v4)

	db.mu.RLock()
	defer db.mu.RUnlock()

	// Binary search for the range containing target
	idx := sort.Search(len(db.ranges), func(i int) bool {
		return db.ranges[i].start > target
	})

	// Check the range before idx (the last range where start <= target)
	if idx > 0 {
		r := db.ranges[idx-1]
		if target >= r.start && target <= r.end {
			return r.country
		}
	}

	return ""
}

// Count returns the number of IP ranges in the database.
func (db *DB) Count() int {
	if db == nil {
		return 0
	}
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.ranges)
}

// Reload reloads the database from a CSV file, atomically swapping the data.
func (db *DB) Reload(path string) error {
	fresh, err := LoadCSV(path)
	if err != nil {
		return err
	}
	db.mu.Lock()
	db.ranges = fresh.ranges
	db.mu.Unlock()
	return nil
}

// StartAutoRefresh starts a background goroutine that periodically checks
// and refreshes the GeoIP database from disk or URL.
// Returns a stop function.
func (db *DB) StartAutoRefresh(path, downloadURL string, interval time.Duration) func() {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Try to download fresh data
				if downloadURL != "" {
					if err := downloadDB(downloadURL, path); err == nil {
						_ = db.Reload(path)
					}
				} else {
					_ = db.Reload(path)
				}
			case <-stop:
				return
			}
		}
	}()
	return func() { close(stop) }
}

// CountryName returns the full name for a country code.
func CountryName(code string) string {
	if name, ok := countryNames[strings.ToUpper(code)]; ok {
		return name
	}
	return code
}

// AutoDownloadURL is the default URL for DB-IP Lite (free, no license key needed).
const AutoDownloadURL = "https://download.db-ip.com/free/dbip-country-lite-2025-03.csv.gz"

// LoadOrDownload tries to load from path. If file doesn't exist or is older than
// maxAge, downloads from the given URL (or AutoDownloadURL if empty).
func LoadOrDownload(path, downloadURL string, maxAge time.Duration) (*DB, error) {
	if path == "" {
		path = "geoip.csv"
	}

	// Check if file exists and is fresh enough
	if info, err := os.Stat(path); err == nil {
		if maxAge <= 0 || time.Since(info.ModTime()) < maxAge {
			return LoadCSV(path)
		}
	}

	// Download
	if downloadURL == "" {
		downloadURL = AutoDownloadURL
	}

	if err := downloadDB(downloadURL, path); err != nil {
		// If download fails but old file exists, use it
		if _, statErr := os.Stat(path); statErr == nil {
			return LoadCSV(path)
		}
		return nil, fmt.Errorf("downloading geoip db: %w", err)
	}

	return LoadCSV(path)
}

// downloadDB downloads a GeoIP CSV (optionally gzipped) from URL to path.
func downloadDB(url, path string) error {
	client := &http.Client{Timeout: 60 * time.Second}
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	// Ensure parent directory exists
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var reader io.Reader = resp.Body

	// Auto-detect gzip by URL suffix or Content-Type
	if strings.HasSuffix(url, ".gz") || strings.Contains(resp.Header.Get("Content-Type"), "gzip") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return fmt.Errorf("gzip decode: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	_, err = io.Copy(f, reader)
	return err
}

// --- Helpers ---

func ipToUint32(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v4)
}

func cidrToRange(cidr string) (start, end uint32, err error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, 0, err
	}

	start = ipToUint32(network.IP.To4())
	ones, bits := network.Mask.Size()
	if bits != 32 {
		return 0, 0, fmt.Errorf("only IPv4 CIDR supported")
	}
	hostBits := uint32(32 - ones)
	end = start | ((1 << hostBits) - 1)

	return start, end, nil
}

// countryNames maps ISO 3166-1 alpha-2 codes to country names.
var countryNames = map[string]string{
	"AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AD": "Andorra",
	"AO": "Angola", "AR": "Argentina", "AM": "Armenia", "AU": "Australia",
	"AT": "Austria", "AZ": "Azerbaijan", "BH": "Bahrain", "BD": "Bangladesh",
	"BY": "Belarus", "BE": "Belgium", "BR": "Brazil", "BG": "Bulgaria",
	"CA": "Canada", "CL": "Chile", "CN": "China", "CO": "Colombia",
	"HR": "Croatia", "CU": "Cuba", "CY": "Cyprus", "CZ": "Czech Republic",
	"DK": "Denmark", "EC": "Ecuador", "EG": "Egypt", "EE": "Estonia",
	"FI": "Finland", "FR": "France", "GE": "Georgia", "DE": "Germany",
	"GH": "Ghana", "GR": "Greece", "HK": "Hong Kong", "HU": "Hungary",
	"IN": "India", "ID": "Indonesia", "IR": "Iran", "IQ": "Iraq",
	"IE": "Ireland", "IL": "Israel", "IT": "Italy", "JP": "Japan",
	"JO": "Jordan", "KZ": "Kazakhstan", "KE": "Kenya", "KR": "South Korea",
	"KP": "North Korea", "KW": "Kuwait", "LV": "Latvia", "LB": "Lebanon",
	"LT": "Lithuania", "LU": "Luxembourg", "MY": "Malaysia", "MX": "Mexico",
	"MA": "Morocco", "NL": "Netherlands", "NZ": "New Zealand", "NG": "Nigeria",
	"NO": "Norway", "PK": "Pakistan", "PA": "Panama", "PE": "Peru",
	"PH": "Philippines", "PL": "Poland", "PT": "Portugal", "QA": "Qatar",
	"RO": "Romania", "RU": "Russia", "SA": "Saudi Arabia", "RS": "Serbia",
	"SG": "Singapore", "SK": "Slovakia", "SI": "Slovenia", "ZA": "South Africa",
	"ES": "Spain", "SE": "Sweden", "CH": "Switzerland", "TW": "Taiwan",
	"TH": "Thailand", "TR": "Turkey", "UA": "Ukraine", "AE": "UAE",
	"GB": "United Kingdom", "US": "United States", "UY": "Uruguay",
	"UZ": "Uzbekistan", "VN": "Vietnam",
}

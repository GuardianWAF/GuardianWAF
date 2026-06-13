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
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var geoipLog = slog.Default().With(slog.String("component", "geoip"))

// DB is a GeoIP database that maps IP addresses to country codes.
type DB struct {
	mu     sync.RWMutex
	ranges []ipRange
}

// AutoRefreshHandle controls a GeoIP auto-refresh goroutine.
type AutoRefreshHandle struct {
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

// Stop stops the auto-refresh goroutine without a deadline.
func (h *AutoRefreshHandle) Stop() {
	_ = h.StopWithContext(context.Background())
}

// StopWithContext stops the auto-refresh goroutine and waits until it exits or
// ctx expires.
func (h *AutoRefreshHandle) StopWithContext(ctx context.Context) error {
	if h == nil {
		return nil
	}
	h.stopOnce.Do(func() {
		close(h.stop)
	})
	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// testAllowPrivate allows tests to bypass SSRF URL validation for httptest servers.
// Must never be set to true in production code.
var testAllowPrivate bool

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
	cleanPath, err := cleanGeoIPFilePath(path, false)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(cleanPath) // #nosec G304 -- path is operator-provided GeoIP DB state, rejected on empty/NUL and cleaned before use.
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

// Ready returns true if the database has loaded IP ranges and can serve lookups.
func (db *DB) Ready() bool {
	if db == nil {
		return false
	}
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.ranges) > 0
}

// Reload reloads the database from a CSV file, atomically swapping the data.
func (db *DB) Reload(path string) error {
	cleanPath, err := cleanGeoIPFilePath(path, false)
	if err != nil {
		return err
	}
	fresh, err := LoadCSV(cleanPath)
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
	handle := db.StartAutoRefreshWithContext(path, downloadURL, interval)
	return handle.Stop
}

// StartAutoRefreshWithContext starts a background refresh goroutine and returns
// a handle that can stop and wait within a caller-provided context.
func (db *DB) StartAutoRefreshWithContext(path, downloadURL string, interval time.Duration) *AutoRefreshHandle {
	cleanPath, pathErr := cleanGeoIPFilePath(path, false)
	if pathErr != nil {
		cleanPath = path
	}
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	handle := &AutoRefreshHandle{
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	go func() {
		defer close(handle.done)
		defer func() {
			if r := recover(); r != nil {
				geoipLog.Error("GeoIP auto-refresh panic recovered", "panic", r)
			}
		}()
		tickerInterval := interval
		if tickerInterval <= 0 {
			tickerInterval = 24 * time.Hour
		}
		ticker := time.NewTicker(tickerInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if pathErr != nil {
					geoipLog.Warn("GeoIP refresh path rejected", "err", pathErr)
					continue
				}
				// Try to download fresh data
				if downloadURL != "" {
					if err := downloadDB(downloadURL, cleanPath); err != nil {
						geoipLog.Warn("GeoIP download failed", "err", err)
					} else if err := db.Reload(cleanPath); err != nil {
						geoipLog.Warn("GeoIP reload after download failed", "err", err)
					}
				} else if err := db.Reload(cleanPath); err != nil {
					geoipLog.Warn("GeoIP reload failed", "err", err)
				}
			case <-handle.stop:
				return
			}
		}
	}()
	return handle
}

// CountryName returns the full name for a country code.
func CountryName(code string) string {
	if name, ok := countryNames[strings.ToUpper(code)]; ok {
		return name
	}
	return code
}

// autoDownloadURL returns the DB-IP Lite download URL for the current month.
func autoDownloadURL() string {
	return fmt.Sprintf("https://download.db-ip.com/free/dbip-country-lite-%s.csv.gz",
		time.Now().Format("2006-01"))
}

// LoadOrDownload tries to load from path. If file doesn't exist or is older than
// maxAge, downloads from the given URL (or AutoDownloadURL if empty).
func LoadOrDownload(path, downloadURL string, maxAge time.Duration) (*DB, error) {
	if path == "" {
		path = "geoip.csv"
	}
	cleanPath, err := cleanGeoIPFilePath(path, false)
	if err != nil {
		return nil, err
	}

	// Check if file exists and is fresh enough
	if info, err := os.Stat(cleanPath); err == nil {
		if maxAge <= 0 || time.Since(info.ModTime()) < maxAge {
			return LoadCSV(cleanPath)
		}
	}

	// Download
	if downloadURL == "" {
		downloadURL = autoDownloadURL()
	}

	if err := downloadDB(downloadURL, cleanPath); err != nil {
		// If download fails but old file exists, use it
		if _, statErr := os.Stat(cleanPath); statErr == nil {
			return LoadCSV(cleanPath)
		}
		return nil, fmt.Errorf("downloading geoip db: %w", err)
	}

	return LoadCSV(cleanPath)
}

// geoipDownloadClient is a shared HTTP client for GeoIP database downloads.
var geoipDownloadClient = newGeoIPDownloadHTTPClient()

const maxGeoIPDownloadSize int64 = 500 * 1024 * 1024

func newGeoIPDownloadHTTPClient() *http.Client {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		transport = &http.Transport{}
	}
	transport = transport.Clone()
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if testAllowPrivate {
			return dialer.DialContext(ctx, network, addr)
		}

		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
			port = ""
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("GeoIP SSRF dial: DNS lookup failed for %q: %w", host, err)
		}
		for _, ip := range ips {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			target := ip.String()
			if port != "" {
				target = net.JoinHostPort(target, port)
			}
			return dialer.DialContext(ctx, network, target)
		}
		return nil, fmt.Errorf("GeoIP SSRF dial: no valid public IPs for %q", host)
	}
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.ExpectContinueTimeout = 1 * time.Second
	transport.IdleConnTimeout = 30 * time.Second

	return &http.Client{
		Timeout:   60 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if testAllowPrivate {
				return nil
			}
			if err := validateURLNotPrivate(req.URL.String()); err != nil {
				return fmt.Errorf("redirect URL rejected: %w", err)
			}
			return nil
		},
	}
}

// downloadDB downloads a GeoIP CSV (optionally gzipped) from URL to path.
func downloadDB(downloadURL, path string) error {
	cleanPath, err := cleanGeoIPFilePath(path, false)
	if err != nil {
		return err
	}
	// SSRF protection: reject URLs targeting private/loopback addresses
	if !testAllowPrivate {
		if err := validateURLNotPrivate(downloadURL); err != nil {
			return fmt.Errorf("download URL rejected: %w", err)
		}
	}

	// Warn on non-HTTPS download URLs
	if strings.HasPrefix(downloadURL, "http://") {
		geoipLog.Warn("GeoIP download URL is not HTTPS — data may be tampered with in transit", "url", downloadURL)
	}

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := geoipDownloadClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) // nolint:errcheck // response body drain; error ignored
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, downloadURL)
	}

	// Ensure parent directory exists
	if dir := filepath.Dir(cleanPath); dir != "" && dir != "." {
		if err = os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}

	f, err := os.Create(cleanPath) // #nosec G304 -- target is operator-provided GeoIP cache state, rejected on empty/NUL and cleaned before write.
	if err != nil {
		return err
	}

	// Limit download to prevent disk exhaustion.
	reader := limitGeoIPDownloadReader(resp.Body, maxGeoIPDownloadSize)

	// Auto-detect gzip by URL suffix or Content-Type
	if strings.HasSuffix(downloadURL, ".gz") || strings.Contains(resp.Header.Get("Content-Type"), "gzip") {
		gz, gzErr := gzip.NewReader(reader)
		if gzErr != nil {
			f.Close()
			return fmt.Errorf("gzip decode: %w", gzErr)
		}
		defer gz.Close()
		reader = limitGeoIPDownloadReader(gz, maxGeoIPDownloadSize)
	}

	_, copyErr := io.Copy(f, reader)
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

type geoIPDownloadLimitReader struct {
	r         io.Reader
	maxBytes  int64
	remaining int64
}

func limitGeoIPDownloadReader(r io.Reader, maxBytes int64) io.Reader {
	return &geoIPDownloadLimitReader{r: r, maxBytes: maxBytes, remaining: maxBytes}
}

func (r *geoIPDownloadLimitReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		var extra [1]byte
		n, err := r.r.Read(extra[:])
		if n > 0 {
			return 0, fmt.Errorf("GeoIP download exceeds %d bytes", r.maxBytes)
		}
		return 0, err
	}
	if int64(len(p)) > r.remaining {
		p = p[:int(r.remaining)]
	}
	n, err := r.r.Read(p)
	r.remaining -= int64(n)
	return n, err
}

// --- Helpers ---

func cleanGeoIPFilePath(path string, allowEmpty bool) (string, error) {
	if strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("geoip file path contains NUL byte")
	}
	if path == "" {
		if allowEmpty {
			return "", nil
		}
		return "", fmt.Errorf("geoip file path must not be empty")
	}
	return filepath.Clean(path), nil
}

// validateURLNotPrivate checks that a URL does not resolve to a private,
// loopback, or link-local IP address (SSRF prevention).
func validateURLNotPrivate(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("must use http or https")
	}
	if u.User != nil {
		return fmt.Errorf("must not include URL userinfo or credentials")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("must include a host")
	}
	if host == "localhost" || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".local") {
		return fmt.Errorf("must not target localhost or internal hosts")
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("must not target private/loopback/link-local addresses")
		}
		return nil
	}
	// Hostname — resolve DNS and check all resulting IPs (prevents DNS rebinding)
	addrs, err := net.LookupHost(host) // #nosec G704 -- preflight DNS check is paired with GeoIP client's SSRF-safe DialContext and redirect validation.
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("hostname resolves to private/loopback address %s", ip)
		}
	}
	return nil
}

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
	hostBits, ok := ipv4HostBits(ones)
	if !ok {
		return 0, 0, fmt.Errorf("invalid IPv4 CIDR mask size %d", ones)
	}
	end = start | ((1 << hostBits) - 1)

	return start, end, nil
}

func ipv4HostBits(ones int) (uint32, bool) {
	if ones < 0 || ones > 32 {
		return 0, false
	}
	// #nosec G115 -- ones is bounded to 0..32 above before uint32 narrowing.
	return uint32(32 - ones), true
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

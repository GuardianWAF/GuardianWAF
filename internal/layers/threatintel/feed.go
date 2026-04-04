package threatintel

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// FeedConfig configures a threat intelligence feed source.
type FeedConfig struct {
	Type          string        `yaml:"type"`    // "file" or "url"
	Path          string        `yaml:"path"`    // File path for type="file"
	URL           string        `yaml:"url"`     // URL for type="url"
	Refresh       time.Duration `yaml:"refresh"` // Refresh interval
	Format        string        `yaml:"format"`  // "json", "jsonl", "csv"
	SkipSSLVerify bool          `yaml:"skip_ssl_verify"`
}

// FeedManager manages a single threat feed source.
type FeedManager struct {
	config   FeedConfig
	client   *http.Client
	stopCh   chan struct{}
	onUpdate func([]ThreatEntry)
}

// ThreatEntry represents a single threat intelligence entry.
type ThreatEntry struct {
	IP     string      `json:"ip,omitempty"`
	CIDR   string      `json:"cidr,omitempty"`
	Domain string      `json:"domain,omitempty"`
	Info   *ThreatInfo `json:"info"`
}

// ThreatInfo contains metadata about a threat.
type ThreatInfo struct {
	Score   int       `json:"score"`
	Type    string    `json:"type"` // malware_c2, spam, phishing, botnet, scanner
	Source  string    `json:"source"`
	Updated time.Time `json:"updated"`
}

// NewFeedManager creates a new feed manager.
func NewFeedManager(config *FeedConfig) *FeedManager {
	return &FeedManager{
		config: *config,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		stopCh: make(chan struct{}),
	}
}

// SetUpdateCallback sets the callback for when new entries are loaded.
func (f *FeedManager) SetUpdateCallback(fn func([]ThreatEntry)) {
	f.onUpdate = fn
}

// LoadOnce loads the feed once without starting a refresh loop.
func (f *FeedManager) LoadOnce(ctx context.Context) ([]ThreatEntry, error) {
	switch f.config.Type {
	case "file":
		return f.loadFile()
	case "url":
		return f.loadURL(ctx)
	default:
		return nil, fmt.Errorf("unknown feed type: %s", f.config.Type)
	}
}

// Start begins the refresh loop.
func (f *FeedManager) Start() {
	// Initial load
	entries, err := f.LoadOnce(context.Background())
	if err == nil && f.onUpdate != nil {
		f.onUpdate(entries)
	}

	// Start refresh loop
	if f.config.Refresh > 0 {
		go f.refreshLoop()
	}
}

// Stop stops the refresh loop.
func (f *FeedManager) Stop() {
	close(f.stopCh)
}

func (f *FeedManager) refreshLoop() {
	ticker := time.NewTicker(f.config.Refresh)
	defer ticker.Stop()

	for {
		select {
		case <-f.stopCh:
			return
		case <-ticker.C:
			entries, err := f.LoadOnce(context.Background())
			if err == nil && f.onUpdate != nil {
				f.onUpdate(entries)
			}
		}
	}
}

func (f *FeedManager) loadFile() ([]ThreatEntry, error) {
	file, err := os.Open(f.config.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to open feed file: %w", err)
	}
	defer file.Close()

	return f.parseReader(file)
}

func (f *FeedManager) loadURL(ctx context.Context) ([]ThreatEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.config.URL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed returned status %d", resp.StatusCode)
	}

	return f.parseReader(resp.Body)
}

func (f *FeedManager) parseReader(r io.Reader) ([]ThreatEntry, error) {
	format := f.config.Format
	if format == "" {
		format = "jsonl" // default
	}

	switch format {
	case "jsonl":
		return f.parseJSONL(r)
	case "json":
		return f.parseJSON(r)
	case "csv":
		return f.parseCSV(r)
	default:
		return nil, fmt.Errorf("unknown feed format: %s", format)
	}
}

// parseJSONL parses JSON Lines format (one JSON object per line).
// Format: {"ip": "1.2.3.4", "score": 90, "type": "malware_c2", "source": "custom"}
func (f *FeedManager) parseJSONL(r io.Reader) ([]ThreatEntry, error) {
	var entries []ThreatEntry
	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var entry struct {
			IP     string `json:"ip"`
			CIDR   string `json:"cidr"`
			Domain string `json:"domain"`
			Score  int    `json:"score"`
			Type   string `json:"type"`
			Source string `json:"source"`
		}

		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue // skip malformed lines
		}

		if entry.IP == "" && entry.CIDR == "" && entry.Domain == "" {
			continue
		}

		info := &ThreatInfo{
			Score:   entry.Score,
			Type:    entry.Type,
			Source:  entry.Source,
			Updated: time.Now(),
		}

		if entry.Score == 0 {
			info.Score = 50 // default score
		}

		entries = append(entries, ThreatEntry{
			IP:     entry.IP,
			CIDR:   entry.CIDR,
			Domain: entry.Domain,
			Info:   info,
		})
	}

	return entries, scanner.Err()
}

// parseJSON parses a JSON array of threat entries.
func (f *FeedManager) parseJSON(r io.Reader) ([]ThreatEntry, error) {
	var data []struct {
		IP     string `json:"ip"`
		CIDR   string `json:"cidr"`
		Domain string `json:"domain"`
		Score  int    `json:"score"`
		Type   string `json:"type"`
		Source string `json:"source"`
	}

	if err := json.NewDecoder(r).Decode(&data); err != nil {
		return nil, err
	}

	entries := make([]ThreatEntry, 0, len(data))
	now := time.Now()

	for _, d := range data {
		if d.IP == "" && d.CIDR == "" && d.Domain == "" {
			continue
		}

		score := d.Score
		if score == 0 {
			score = 50
		}

		entries = append(entries, ThreatEntry{
			IP:     d.IP,
			CIDR:   d.CIDR,
			Domain: d.Domain,
			Info: &ThreatInfo{
				Score:   score,
				Type:    d.Type,
				Source:  d.Source,
				Updated: now,
			},
		})
	}

	return entries, nil
}

// parseCSV parses CSV format: ip,score,type,source
func (f *FeedManager) parseCSV(r io.Reader) ([]ThreatEntry, error) {
	var entries []ThreatEntry
	scanner := bufio.NewScanner(r)
	lineNum := 0
	now := time.Now()

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ",")

		ip := strings.TrimSpace(parts[0])
		if ip == "" {
			continue
		}

		score := 50
		threatType := "unknown"
		source := "csv"

		if len(parts) > 1 {
			if s, err := parseInt(strings.TrimSpace(parts[1])); err == nil {
				score = s
			}
		}
		if len(parts) > 2 {
			threatType = strings.TrimSpace(parts[2])
		}
		if len(parts) > 3 {
			source = strings.TrimSpace(parts[3])
		}

		entry := ThreatEntry{
			Info: &ThreatInfo{
				Score:   score,
				Type:    threatType,
				Source:  source,
				Updated: now,
			},
		}

		// Determine if IP or CIDR
		switch {
		case strings.Contains(ip, "/"):
			entry.CIDR = ip
		case net.ParseIP(ip) != nil:
			entry.IP = ip
		default:
			// Treat as domain
			entry.Domain = ip
		}

		entries = append(entries, entry)
	}

	return entries, scanner.Err()
}

func parseInt(s string) (int, error) {
	var n int
	var neg bool
	if s != "" && s[0] == '-' {
		neg = true
		s = s[1:]
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid integer")
		}
		n = n*10 + int(c-'0')
	}
	if neg {
		n = -n
	}
	return n, nil
}

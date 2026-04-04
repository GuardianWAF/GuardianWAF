package replay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Replayer handles request replay.
type Replayer struct {
	config     *ReplayerConfig
	client     *http.Client
	mu         sync.RWMutex
	running    bool
	cancelFunc context.CancelFunc
	stats      ReplayStats
}

// ReplayerConfig for replay engine.
type ReplayerConfig struct {
	Enabled       bool          `yaml:"enabled"`
	TargetBaseURL string        `yaml:"target_base_url"`
	RateLimit     int           `yaml:"rate_limit"`      // requests per second
	Concurrency   int           `yaml:"concurrency"`     // parallel workers
	Timeout       time.Duration `yaml:"timeout"`
	FollowRedirects bool        `yaml:"follow_redirects"`
	ModifyHost    bool          `yaml:"modify_host"`     // replace original host
	PreserveIDs   bool          `yaml:"preserve_ids"`    // keep X-Request-ID
	DryRun        bool          `yaml:"dry_run"`         // log only, don't send
	Headers       map[string]string `yaml:"headers"`       // additional headers
}

// DefaultReplayerConfig returns default config.
func DefaultReplayerConfig() *ReplayerConfig {
	return &ReplayerConfig{
		Enabled:         false,
		RateLimit:       100,
		Concurrency:     10,
		Timeout:         30 * time.Second,
		FollowRedirects: false,
		ModifyHost:      true,
		PreserveIDs:     false,
		DryRun:          false,
		Headers:         make(map[string]string),
	}
}

// ReplayStats tracks replay performance.
type ReplayStats struct {
	StartedAt      time.Time     `json:"started_at"`
	CompletedAt    time.Time     `json:"completed_at,omitempty"`
	TotalRequests  int           `json:"total_requests"`
	SuccessCount   int           `json:"success_count"`
	ErrorCount     int           `json:"error_count"`
	SkippedCount   int           `json:"skipped_count"`
	TotalDuration  time.Duration `json:"total_duration"`
	AvgLatency     time.Duration `json:"avg_latency"`
	Errors         []string      `json:"errors,omitempty"`
}

// ReplayJob represents a single replay task.
type ReplayJob struct {
	ID       string
	File     string
	Filter   ReplayFilter
	Schedule *ReplaySchedule
}

// ReplayFilter for selective replay.
type ReplayFilter struct {
	Methods    []string
	Paths      []string
	StatusCode int    // 0 = any
	FromTime   time.Time
	ToTime     time.Time
	Contains   string // body contains
}

// ReplaySchedule for automated replay.
type ReplaySchedule struct {
	Enabled   bool      `yaml:"enabled"`
	Interval  time.Duration `yaml:"interval"`
	StartTime time.Time     `yaml:"start_time,omitempty"`
	Repeat    int           `yaml:"repeat"` // 0 = infinite
}

// NewReplayer creates a new replay engine.
func NewReplayer(cfg *ReplayerConfig) *Replayer {
	if cfg == nil {
		cfg = DefaultReplayerConfig()
	}

	return &Replayer{
		config: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if !cfg.FollowRedirects {
					return http.ErrUseLastResponse
				}
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		stats: ReplayStats{},
	}
}

// ReplayFile replays all requests from a recording file.
func (r *Replayer) ReplayFile(ctx context.Context, filePath string, filter ReplayFilter) (*ReplayStats, error) {
	if !r.config.Enabled {
		return nil, fmt.Errorf("replayer is disabled")
	}

	r.mu.Lock()
	r.running = true
	r.stats = ReplayStats{
		StartedAt: time.Now().UTC(),
		Errors:    make([]string, 0),
	}
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		r.running = false
		r.stats.CompletedAt = time.Now().UTC()
		r.mu.Unlock()
	}()

	// Open file
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open recording: %w", err)
	}
	defer f.Close()

	// Parse and replay requests
	records, err := r.parseRecords(f)
	if err != nil {
		return nil, fmt.Errorf("failed to parse records: %w", err)
	}

	// Filter records
	filtered := r.filterRecords(records, filter)

	// Replay with concurrency control
	return r.replayBatch(ctx, filtered)
}

// ReplayRecording replays from storage path.
func (r *Replayer) ReplayRecording(ctx context.Context, storagePath, filename string, filter ReplayFilter) (*ReplayStats, error) {
	filePath := filepath.Join(storagePath, filename)
	return r.ReplayFile(ctx, filePath, filter)
}

// parseRecords reads records from file.
func (r *Replayer) parseRecords(rdr io.Reader) ([]*RecordedRequest, error) {
	var records []*RecordedRequest

	scanner := bufio.NewScanner(rdr)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var rec RecordedRequest
		if err := json.Unmarshal(line, &rec); err != nil {
			continue // Skip malformed lines
		}

		records = append(records, &rec)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return records, nil
}

// filterRecords applies filters.
func (r *Replayer) filterRecords(records []*RecordedRequest, filter ReplayFilter) []*RecordedRequest {
	if filter.StatusCode == 0 && len(filter.Methods) == 0 && len(filter.Paths) == 0 &&
		filter.FromTime.IsZero() && filter.ToTime.IsZero() && filter.Contains == "" {
		return records
	}

	var filtered []*RecordedRequest
	for _, rec := range records {
		// Method filter
		if len(filter.Methods) > 0 && !contains(filter.Methods, rec.Method) {
			continue
		}

		// Path filter
		if len(filter.Paths) > 0 {
			match := false
			for _, p := range filter.Paths {
				if strings.Contains(rec.Path, p) {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}

		// Status code filter
		if filter.StatusCode > 0 && rec.ResponseStatus != filter.StatusCode {
			continue
		}

		// Time range filter
		if !filter.FromTime.IsZero() && rec.Timestamp.Before(filter.FromTime) {
			continue
		}
		if !filter.ToTime.IsZero() && rec.Timestamp.After(filter.ToTime) {
			continue
		}

		// Body content filter
		if filter.Contains != "" && !strings.Contains(string(rec.Body), filter.Contains) {
			continue
		}

		filtered = append(filtered, rec)
	}

	return filtered
}

// replayBatch replays requests with rate limiting.
func (r *Replayer) replayBatch(ctx context.Context, records []*RecordedRequest) (*ReplayStats, error) {
	stats := &ReplayStats{
		StartedAt: time.Now().UTC(),
		Errors:    make([]string, 0),
	}

	total := len(records)
	if total == 0 {
		return stats, nil
	}

	// Rate limiter
	rateLimiter := time.NewTicker(time.Second / time.Duration(r.config.RateLimit))
	defer rateLimiter.Stop()

	// Worker pool
	var wg sync.WaitGroup
	sem := make(chan struct{}, r.config.Concurrency)

	var mu sync.Mutex
	var totalLatency time.Duration

	for i, rec := range records {
		select {
		case <-ctx.Done():
			return stats, ctx.Err()
		case <-rateLimiter.C:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(idx int, record *RecordedRequest) {
			defer wg.Done()
			defer func() { <-sem }()

			// Dry run mode
			if r.config.DryRun {
				fmt.Printf("[DRY-RUN] #%d %s %s\n", idx, record.Method, record.URL)
				mu.Lock()
				stats.TotalRequests++
				mu.Unlock()
				return
			}

			// Replay request
			start := time.Now()
			err := r.replayRequest(ctx, record)
			latency := time.Since(start)

			mu.Lock()
			stats.TotalRequests++
			totalLatency += latency

			if err != nil {
				stats.ErrorCount++
				if len(stats.Errors) < 10 { // Keep last 10 errors
					stats.Errors = append(stats.Errors, fmt.Sprintf("#%d: %v", idx, err))
				}
			} else {
				stats.SuccessCount++
			}
			mu.Unlock()
		}(i, rec)
	}

	wg.Wait()

	stats.CompletedAt = time.Now().UTC()
	stats.TotalDuration = stats.CompletedAt.Sub(stats.StartedAt)
	if stats.TotalRequests > 0 {
		stats.AvgLatency = totalLatency / time.Duration(stats.TotalRequests)
	}

	// Update internal stats
	r.mu.Lock()
	r.stats = *stats
	r.mu.Unlock()

	return stats, nil
}

// replayRequest sends a single request.
func (r *Replayer) replayRequest(ctx context.Context, rec *RecordedRequest) error {
	// Build target URL
	targetURL := rec.URL
	if r.config.TargetBaseURL != "" {
		u, err := url.Parse(rec.URL)
		if err != nil {
			return err
		}

		base, err := url.Parse(r.config.TargetBaseURL)
		if err != nil {
			return err
		}

		// Replace scheme and host
		u.Scheme = base.Scheme
		if r.config.ModifyHost {
			u.Host = base.Host
		}
		targetURL = u.String()
	}

	// Create request
	body := bytes.NewReader(rec.Body)
	req, err := http.NewRequestWithContext(ctx, rec.Method, targetURL, body)
	if err != nil {
		return err
	}

	// Copy headers
	for k, v := range rec.Headers {
		// Skip hop-by-hop headers
		if isHopByHop(k) {
			continue
		}
		req.Header.Set(k, v)
	}

	// Add additional headers
	for k, v := range r.config.Headers {
		req.Header.Set(k, v)
	}

	// Handle request ID
	if !r.config.PreserveIDs {
		req.Header.Set("X-Replayed", "true")
		req.Header.Set("X-Original-Time", rec.Timestamp.Format(time.RFC3339))
	}

	// Send request
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Drain body
	io.Copy(io.Discard, resp.Body)

	return nil
}

// isHopByHop checks if header should not be forwarded.
func isHopByHop(header string) bool {
	hopByHop := []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "TE", "Trailers", "Transfer-Encoding", "Upgrade",
	}
	for _, h := range hopByHop {
		if strings.EqualFold(header, h) {
			return true
		}
	}
	return false
}

// IsRunning returns if replay is active.
func (r *Replayer) IsRunning() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.running
}

// GetStats returns current replay stats.
func (r *Replayer) GetStats() ReplayStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.stats
}

// Stop stops active replay.
func (r *Replayer) Stop() {
	r.mu.Lock()
	if r.cancelFunc != nil {
		r.cancelFunc()
	}
	r.mu.Unlock()
}

// contains checks if slice contains item.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

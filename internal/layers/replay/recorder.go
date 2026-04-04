// Package replay provides HTTP request recording and replay functionality.
package replay

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RecordFormat defines how requests are stored.
type RecordFormat string

const (
	FormatJSON  RecordFormat = "json"
	FormatBinary RecordFormat = "binary"
)

// Config for replay layer.
type Config struct {
	Enabled        bool         `yaml:"enabled"`
	StoragePath    string       `yaml:"storage_path"`
	Format         RecordFormat `yaml:"format"`
	MaxFileSize    int64        `yaml:"max_file_size"`     // MB
	MaxFiles       int          `yaml:"max_files"`
	RetentionDays  int          `yaml:"retention_days"`
	CaptureRequest bool         `yaml:"capture_request"`
	CaptureResponse bool        `yaml:"capture_response"`
	CaptureHeaders []string     `yaml:"capture_headers"` // empty = all
	SkipPaths      []string     `yaml:"skip_paths"`
	SkipMethods    []string     `yaml:"skip_methods"`
	Compress       bool         `yaml:"compress"`
}

// DefaultConfig returns default replay config.
func DefaultConfig() *Config {
	return &Config{
		Enabled:         false,
		StoragePath:     "data/replay",
		Format:          FormatJSON,
		MaxFileSize:     100, // 100MB
		MaxFiles:        10,
		RetentionDays:   30,
		CaptureRequest:  true,
		CaptureResponse: false,
		SkipPaths:       []string{"/healthz", "/metrics", "/gwaf"},
		SkipMethods:     []string{"OPTIONS", "HEAD"},
		Compress:        true,
	}
}

// Recorder handles request recording.
type Recorder struct {
	config     *Config
	mu         sync.Mutex
	currentFile *os.File
	currentSize int64
	fileIndex   int
	buffer      *bufio.Writer
}

// RecordedRequest represents a captured HTTP request.
type RecordedRequest struct {
	Timestamp   time.Time         `json:"timestamp"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Path        string            `json:"path"`
	Query       string            `json:"query"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        []byte            `json:"body,omitempty"`
	RemoteAddr  string            `json:"remote_addr"`
	RequestID   string            `json:"request_id,omitempty"`

	// Response data (if captured)
	ResponseStatus  int               `json:"response_status,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	ResponseBody    []byte            `json:"response_body,omitempty"`
	DurationMs      int64             `json:"duration_ms,omitempty"`
}

// NewRecorder creates a new request recorder.
func NewRecorder(cfg *Config) (*Recorder, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Ensure storage directory exists
	if err := os.MkdirAll(cfg.StoragePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create replay directory: %w", err)
	}

	r := &Recorder{
		config: cfg,
	}

	// Open initial file
	if err := r.rotateFile(); err != nil {
		return nil, err
	}

	// Start cleanup goroutine
	go r.cleanupRoutine()

	return r, nil
}

// Record captures a request/response pair.
func (r *Recorder) Record(req *http.Request, resp *http.Response, duration time.Duration) error {
	if !r.shouldRecord(req) {
		return nil
	}

	record := &RecordedRequest{
		Timestamp:  time.Now().UTC(),
		Method:     req.Method,
		URL:        req.URL.String(),
		Path:       req.URL.Path,
		Query:      req.URL.RawQuery,
		RemoteAddr: req.RemoteAddr,
		DurationMs: duration.Milliseconds(),
	}

	// Extract request ID if present
	if reqID := req.Header.Get("X-Request-ID"); reqID != "" {
		record.RequestID = reqID
	}

	// Capture headers
	if len(r.config.CaptureHeaders) > 0 {
		record.Headers = make(map[string]string)
		for _, h := range r.config.CaptureHeaders {
			if v := req.Header.Get(h); v != "" {
				record.Headers[h] = v
			}
		}
	} else {
		record.Headers = headersToMap(req.Header)
	}

	// Capture request body
	if r.config.CaptureRequest && req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err == nil && len(body) > 0 {
			record.Body = body
			// Restore body for further processing
			req.Body = io.NopCloser(bytes.NewReader(body))
		}
	}

	// Capture response
	if r.config.CaptureResponse && resp != nil {
		record.ResponseStatus = resp.StatusCode
		record.ResponseHeaders = headersToMap(resp.Header)
		if resp.Body != nil {
			body, err := io.ReadAll(resp.Body)
			if err == nil && len(body) > 0 {
				record.ResponseBody = body
				// Restore body
				resp.Body = io.NopCloser(bytes.NewReader(body))
			}
		}
	}

	return r.writeRecord(record)
}

// shouldRecord checks if request should be recorded.
func (r *Recorder) shouldRecord(req *http.Request) bool {
	// Check skip methods
	for _, m := range r.config.SkipMethods {
		if req.Method == m {
			return false
		}
	}

	// Check skip paths
	for _, p := range r.config.SkipPaths {
		if hasPrefix(req.URL.Path, p) {
			return false
		}
	}

	return true
}

// writeRecord writes record to file.
func (r *Recorder) writeRecord(record *RecordedRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if we need to rotate
	if r.currentSize > r.config.MaxFileSize*1024*1024 {
		if err := r.rotateFile(); err != nil {
			return err
		}
	}

	var data []byte
	var err error

	switch r.config.Format {
	case FormatBinary:
		data, err = r.encodeBinary(record)
	default:
		data, err = json.Marshal(record)
		if err == nil {
			data = append(data, '\n')
		}
	}

	if err != nil {
		return err
	}

	n, err := r.buffer.Write(data)
	if err != nil {
		return err
	}

	r.currentSize += int64(n)
	return r.buffer.Flush()
}

// encodeBinary encodes record in binary format (HTTP dump).
func (r *Recorder) encodeBinary(record *RecordedRequest) ([]byte, error) {
	// Reconstruct request for dumping
	req, err := http.NewRequest(record.Method, record.URL, bytes.NewReader(record.Body))
	if err != nil {
		return nil, err
	}

	for k, v := range record.Headers {
		req.Header.Set(k, v)
	}

	dump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		return nil, err
	}

	return dump, nil
}

// rotateFile switches to a new output file.
func (r *Recorder) rotateFile() error {
	if r.buffer != nil {
		r.buffer.Flush()
	}

	if r.currentFile != nil {
		r.currentFile.Close()
		r.fileIndex++
	}

	// Remove old files if exceeding max
	r.cleanupOldFiles()

	filename := filepath.Join(r.config.StoragePath, fmt.Sprintf("requests-%s-%03d.log",
		time.Now().Format("YYYYMMDD"), r.fileIndex))

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	r.currentFile = f
	r.buffer = bufio.NewWriter(f)
	r.currentSize = 0

	return nil
}

// cleanupOldFiles removes files exceeding retention.
func (r *Recorder) cleanupOldFiles() {
	entries, err := os.ReadDir(r.config.StoragePath)
	if err != nil {
		return
	}

	// Group by date
	filesByDate := make(map[string][]os.DirEntry)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if len(name) < 8 {
			continue
		}
		date := name[9:17] // requests-YYYYMMDD-XXX.log
		filesByDate[date] = append(filesByDate[date], entry)
	}

	// Remove files older than retention
	cutoff := time.Now().AddDate(0, 0, -r.config.RetentionDays)
	for date, files := range filesByDate {
		t, err := time.Parse("YYYYMMDD", date)
		if err != nil {
			continue
		}

		if t.Before(cutoff) {
			for _, f := range files {
				os.Remove(filepath.Join(r.config.StoragePath, f.Name()))
			}
		}
	}

	// Keep only max_files most recent
	if len(entries) > r.config.MaxFiles {
		// Sort by modification time and remove oldest
		// Simplified: just remove oldest files
		for i := 0; i < len(entries)-r.config.MaxFiles; i++ {
			if !entries[i].IsDir() {
				os.Remove(filepath.Join(r.config.StoragePath, entries[i].Name()))
			}
		}
	}
}

// cleanupRoutine periodically cleans up old files.
func (r *Recorder) cleanupRoutine() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		r.cleanupOldFiles()
	}
}

// Close closes the recorder.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.buffer != nil {
		r.buffer.Flush()
	}

	if r.currentFile != nil {
		return r.currentFile.Close()
	}

	return nil
}

// ListRecordings returns available recording files.
func (r *Recorder) ListRecordings() ([]string, error) {
	entries, err := os.ReadDir(r.config.StoragePath)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, entry.Name())
		}
	}

	return files, nil
}

// GetStats returns recorder statistics.
func (r *Recorder) GetStats() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()

	return map[string]any{
		"enabled":     r.config.Enabled,
		"format":      r.config.Format,
		"current_file": r.fileIndex,
		"current_size": r.currentSize,
	}
}

// headersToMap converts http.Header to map.
func headersToMap(h http.Header) map[string]string {
	m := make(map[string]string)
	for k, v := range h {
		if len(v) > 0 {
			m[k] = v[0]
		}
	}
	return m
}

// hasPrefix checks if s has prefix (case insensitive for paths).
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

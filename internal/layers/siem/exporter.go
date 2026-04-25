package siem

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Exporter exports security events to SIEM systems.
type Exporter struct {
	config     *Config
	formatter  *Formatter
	client     *http.Client
	eventChan  chan *Event
	wg         sync.WaitGroup
	stopChan   chan struct{}
	logFn      func(level string, msg string, args ...any)
}

// Config for SIEM exporter.
type Config struct {
	Enabled      bool          `yaml:"enabled"`
	Endpoint     string        `yaml:"endpoint"`
	Format       Format        `yaml:"format"`
	APIKey       string        `yaml:"api_key"`
	Index        string        `yaml:"index"`
	BatchSize    int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
	Timeout      time.Duration `yaml:"timeout"`
	SkipVerify   bool          `yaml:"skip_verify"`
	Fields       map[string]string `yaml:"fields"`
}

// DefaultConfig returns default SIEM configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled:       false,
		Format:        FormatJSON,
		BatchSize:     100,
		FlushInterval: 5 * time.Second,
		Timeout:       10 * time.Second,
		Fields:        make(map[string]string),
	}
}

// NewExporter creates a new SIEM exporter.
func NewExporter(cfg *Config) *Exporter {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if cfg.BatchSize == 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	formatter := NewFormatter(cfg.Format, "", "", "")

	// Validate endpoint URL to prevent SSRF
	if cfg.Endpoint != "" {
		if err := validateSIEMEndpoint(cfg.Endpoint); err != nil {
			log.Printf("[siem] ERROR: endpoint URL validation failed: %v", err)
			return nil
		}
	}

	// TLS certificate verification is always enforced for SIEM connections.
	// The SkipVerify config field is ignored to prevent MITM attacks.
	if cfg.SkipVerify {
		log.Printf("[siem] WARNING: SkipVerify config option is ignored — TLS verification is always enforced")
	}

	transport := &http.Transport{
		DialContext:           siemSSRFDialContext(),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false, // Always enforce TLS verification
		},
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:  10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	return &Exporter{
		config:    cfg,
		formatter: formatter,
		client: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
		},
		eventChan: make(chan *Event, cfg.BatchSize*2),
		stopChan:  make(chan struct{}),
		logFn:     func(_, _ string, _ ...any) {},
	}
}

// Start starts the exporter.
func (e *Exporter) Start() {
	if !e.config.Enabled {
		return
	}

	e.wg.Add(1)
	go e.batchProcessor()
}

// Stop stops the exporter.
func (e *Exporter) Stop() {
	select {
	case <-e.stopChan:
		return
	default:
		close(e.stopChan)
	}
	e.wg.Wait()
}

// Export exports a single event.
func (e *Exporter) Export(event *Event) {
	if !e.config.Enabled {
		return
	}

	// Add configured fields (copy to avoid mutating shared event)
	if len(e.config.Fields) > 0 {
		fields := make(map[string]string, len(event.Fields)+len(e.config.Fields))
		for k, v := range event.Fields {
			fields[k] = v
		}
		for k, v := range e.config.Fields {
			fields[k] = v
		}
		event.Fields = fields
	}

	select {
	case e.eventChan <- event:
	default:
		// Channel full, drop event and log
		e.logFn("warn", "SIEM event channel full, dropping event for %s %s", event.Method, event.Path)
	}
}

// ExportBatch exports multiple events.
func (e *Exporter) ExportBatch(events []*Event) {
	for _, event := range events {
		e.Export(event)
	}
}

// batchProcessor processes events in batches.
func (e *Exporter) batchProcessor() {
	defer e.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[siem] goroutine panic: %v", r)
		}
	}()

	flushInterval := e.config.FlushInterval
	if flushInterval <= 0 {
		flushInterval = 30 * time.Second
	}
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	batch := make([]*Event, 0, e.config.BatchSize)

	for {
		select {
		case event := <-e.eventChan:
			batch = append(batch, event)

			if len(batch) >= e.config.BatchSize {
				if err := e.sendBatch(batch); err != nil {
					e.logFn("warn", "SIEM batch send failed: %v", err)
				}
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				if err := e.sendBatch(batch); err != nil {
					e.logFn("warn", "SIEM batch send failed: %v", err)
				}
				batch = batch[:0]
			}

		case <-e.stopChan:
			// Flush remaining events
			if len(batch) > 0 {
				if err := e.sendBatch(batch); err != nil {
					e.logFn("warn", "SIEM final batch send failed: %v", err)
				}
			}
			return
		}
	}
}

// sendBatch sends a batch of events to the SIEM.
func (e *Exporter) sendBatch(events []*Event) error {
	if len(events) == 0 {
		return nil
	}

	// Format events based on target SIEM
	var data []byte
	var contentType string

	switch e.config.Format {
	case FormatSplunk:
		data = e.formatSplunkBatch(events)
		contentType = "application/json"
	case FormatElastic:
		data = e.formatElasticBatch(events)
		contentType = "application/x-ndjson"
	case FormatCEF, FormatLEEF:
		data = e.formatTextBatch(events)
		contentType = "text/plain"
	default:
		data = e.formatJSONBatch(events)
		contentType = "application/json"
	}

	if data == nil {
		return fmt.Errorf("failed to format SIEM batch")
	}

	// Send HTTP request
	req, err := http.NewRequest("POST", e.config.Endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", contentType)

	if e.config.APIKey != "" {
		switch e.config.Format {
		case FormatSplunk:
			req.Header.Set("Authorization", "Splunk "+e.config.APIKey)
		case FormatElastic:
			req.Header.Set("Authorization", "ApiKey "+e.config.APIKey)
		default:
			req.Header.Set("Authorization", "Bearer "+e.config.APIKey)
		}
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("SIEM returned error: %s", resp.Status)
	}

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	return nil
}

// formatJSONBatch formats events as JSON array.
func (e *Exporter) formatJSONBatch(events []*Event) []byte {
	data, err := json.Marshal(events)
	if err != nil {
		log.Printf("[siem] failed to marshal JSON batch: %v", err)
		return nil
	}
	return data
}

// formatSplunkBatch formats events for Splunk HEC.
func (e *Exporter) formatSplunkBatch(events []*Event) []byte {
	var buf bytes.Buffer

	for _, event := range events {
		splunkEvent := map[string]any{
			"time":       event.Timestamp.Unix(),
			"source":     e.config.Index,
			"sourcetype": "guardianwaf",
			"host":       "guardianwaf",
			"event":      event,
		}

		data, err := json.Marshal(splunkEvent)
		if err != nil {
			continue
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}

	return buf.Bytes()
}

// formatElasticBatch formats events for Elasticsearch bulk API.
func (e *Exporter) formatElasticBatch(events []*Event) []byte {
	var buf bytes.Buffer

	for _, event := range events {
		// Index metadata
		index := map[string]any{
			"index": map[string]any{
				"_index": fmt.Sprintf("%s-%s", e.config.Index, event.Timestamp.Format("2006.01.02")),
			},
		}

		indexData, err := json.Marshal(index)
		if err != nil {
			continue
		}
		buf.Write(indexData)
		buf.WriteByte('\n')

		// Event data
		eventData, err := json.Marshal(event)
		if err != nil {
			continue
		}
		buf.Write(eventData)
		buf.WriteByte('\n')
	}

	return buf.Bytes()
}

// formatTextBatch formats events as text (CEF/LEEF).
func (e *Exporter) formatTextBatch(events []*Event) []byte {
	var buf bytes.Buffer

	for _, event := range events {
		formatted, _ := e.formatter.Format(event)
		buf.WriteString(formatted)
		buf.WriteByte('\n')
	}

	return buf.Bytes()
}

// validateSIEMEndpoint checks that the SIEM endpoint URL is safe (not targeting internal networks).
// It resolves DNS to detect hostnames that point to private/internal IPs.
func validateSIEMEndpoint(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("SIEM endpoint must use HTTPS, got %q", u.Scheme)
	}
	return validateSIEMHostNotPrivate(u.Hostname())
}

// validateSIEMHostNotPrivate checks that a hostname does not resolve to a private/internal IP.
func validateSIEMHostNotPrivate(host string) error {
	if host == "localhost" || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".local") {
		return fmt.Errorf("SIEM endpoint must not target localhost or internal hosts")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return fmt.Errorf("SIEM endpoint must not target private/loopback addresses")
		}
		return nil
	}
	// DNS resolution check to prevent SSRF via hostnames resolving to private IPs
	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("SIEM endpoint hostname DNS lookup failed: %w", err)
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return fmt.Errorf("SIEM endpoint hostname resolves to private address %s", ip)
		}
	}
	return nil
}

// Name returns the exporter name.
func (e *Exporter) Name() string {
	return fmt.Sprintf("siem-%s", e.config.Format)
}

// IsEnabled returns whether the exporter is enabled.
func (e *Exporter) IsEnabled() bool {
	return e.config.Enabled
}

// siemSSRFDialContext returns a DialContext that validates resolved IPs at
// connection time to prevent DNS rebinding (TOCTOU) attacks on SIEM endpoints.
// Resolves DNS, validates all IPs, then dials the validated IP directly — avoids
// a second DNS resolution by the dialer that could be rebinding-attacked.
func siemSSRFDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
			port = ""
		}
		// Resolve DNS and validate all resulting IPs
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("SIEM SSRF: DNS lookup failed for %q: %w", host, err)
		}
		var validIP net.IP
		for _, ip := range ips {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			validIP = ip
			break
		}
		if validIP == nil {
			return nil, fmt.Errorf("SIEM SSRF: no valid public IPs for %q", host)
		}
		// Dial the validated IP directly — avoids TOCTOU via DNS rebinding
		target := net.JoinHostPort(validIP.String(), port)
		return dialer.DialContext(ctx, network, target)
	}
}

package siem

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
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

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.SkipVerify,
		},
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
	close(e.stopChan)
	e.wg.Wait()
}

// Export exports a single event.
func (e *Exporter) Export(event *Event) {
	if !e.config.Enabled {
		return
	}

	// Add configured fields
	for k, v := range e.config.Fields {
		if event.Fields == nil {
			event.Fields = make(map[string]string)
		}
		event.Fields[k] = v
	}

	select {
	case e.eventChan <- event:
	default:
		// Channel full, drop event
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

	ticker := time.NewTicker(e.config.FlushInterval)
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
		return fmt.Errorf("SIEM returned error: %s", resp.Status)
	}

	return nil
}

// formatJSONBatch formats events as JSON array.
func (e *Exporter) formatJSONBatch(events []*Event) []byte {
	data, _ := json.Marshal(events)
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

		data, _ := json.Marshal(splunkEvent)
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

		indexData, _ := json.Marshal(index)
		buf.Write(indexData)
		buf.WriteByte('\n')

		// Event data
		eventData, _ := json.Marshal(event)
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

// Name returns the exporter name.
func (e *Exporter) Name() string {
	return fmt.Sprintf("siem-%s", e.config.Format)
}

// IsEnabled returns whether the exporter is enabled.
func (e *Exporter) IsEnabled() bool {
	return e.config.Enabled
}

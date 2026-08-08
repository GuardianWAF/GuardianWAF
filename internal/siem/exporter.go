package siem

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// ExporterConfig holds the settings for a SIEM exporter.
type ExporterConfig struct {
	Endpoint      string        // host:port
	Format        string        // "cef" or "json" (default: cef)
	FlushInterval time.Duration // max time between flushes (default: 1s)
	BatchSize     int           // events per batch (default: 100)
	Timeout       time.Duration // connect/write timeout (default: 5s)
	SkipVerify    bool          // skip TLS cert verification
	Hostname      string        // syslog hostname field
	ExtraFields   map[string]string
	UseTLS        bool // use TLS transport
}

// ExporterStats reports bounded operational counters.
type ExporterStats struct {
	Sent         int64
	Failed       int64
	Dropped      int64
	Connects     int64
	EventsQueued int64
}

// Exporter subscribes to events, filters for block/challenge, formats them as
// CEF, and sends them via syslog (TCP or TLS) to a SIEM endpoint. It is fully
// asynchronous: Export never blocks the request path.
type Exporter struct {
	cfg ExporterConfig

	mu     sync.Mutex
	conn   net.Conn
	closed bool
	wg     sync.WaitGroup
	ch     chan engine.Event

	sent         atomic.Int64
	failed       atomic.Int64
	dropped      atomic.Int64
	connects     atomic.Int64
	eventsQueued atomic.Int64
}

// NewExporter creates a SIEM exporter and starts its background flush loop.
func NewExporter(cfg ExporterConfig) (*Exporter, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("siem endpoint is required")
	}
	host, port, err := net.SplitHostPort(cfg.Endpoint)
	if err != nil || port == "" {
		return nil, fmt.Errorf("siem endpoint %q must be host:port: %w", cfg.Endpoint, err)
	}

	if cfg.Format == "" {
		cfg.Format = "cef"
	}
	if cfg.Format != "cef" && cfg.Format != "json" {
		return nil, fmt.Errorf("unsupported siem format %q (supported: cef, json)", cfg.Format)
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Hostname == "" {
		cfg.Hostname = host
	}

	bufferSize := cfg.BatchSize * 4
	if bufferSize < 256 {
		bufferSize = 256
	}

	exp := &Exporter{
		cfg: cfg,
		ch:  make(chan engine.Event, bufferSize),
	}

	exp.wg.Add(1)
	go exp.run()

	return exp, nil
}

// run is the background flush loop: collects events from the channel, batches
// them, and writes to the SIEM endpoint.
func (e *Exporter) run() {
	defer e.wg.Done()
	defer func() {
		e.mu.Lock()
		if e.conn != nil {
			e.conn.Close()
			e.conn = nil
		}
		e.mu.Unlock()
	}()

	batch := make([]engine.Event, 0, e.cfg.BatchSize)
	timer := time.NewTimer(e.cfg.FlushInterval)
	defer timer.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		e.flushBatch(batch)
		batch = batch[:0]
	}

	for {
		select {
		case ev, ok := <-e.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, ev)
			if len(batch) >= e.cfg.BatchSize {
				flush()
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(e.cfg.FlushInterval)
			}

		case <-timer.C:
			flush()
			timer.Reset(e.cfg.FlushInterval)
		}
	}
}

// flushBatch formats and sends a batch of events to the SIEM endpoint.
func (e *Exporter) flushBatch(batch []engine.Event) {
	var lines []string
	for _, ev := range batch {
		line := e.formatEvent(ev)
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return
	}

	data := strings.Join(lines, "\n") + "\n"
	err := e.write(data)
	if err != nil {
		e.failed.Add(int64(len(lines)))
		slog.Default().Warn("siem export failed", "error", err, "events", len(lines))
		return
	}
	e.sent.Add(int64(len(lines)))
}

// formatEvent renders an event in the configured format (CEF or JSON).
func (e *Exporter) formatEvent(ev engine.Event) string {
	switch e.cfg.Format {
	case "json":
		return formatJSON(ev)
	default:
		return EncodeCEF(ev, "GuardianWAF", version)
	}
}

// write sends data to the SIEM endpoint, reconnecting if necessary.
func (e *Exporter) write(data string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Note: we intentionally do NOT check e.closed here. Close() sets the
	// flag before closing the channel, which triggers the final flush in
	// run(). Blocking the final flush on closed would discard all pending
	// events on shutdown.

	// Try writing to existing connection.
	if e.conn != nil {
		_, err := io.WriteString(e.conn, data)
		if err == nil {
			return nil
		}
		// Connection is dead — close and reconnect.
		e.conn.Close()
		e.conn = nil
	}

	// Establish a new connection.
	conn, err := e.dial()
	if err != nil {
		return fmt.Errorf("siem connect: %w", err)
	}
	e.connects.Add(1)
	e.conn = conn

	_, err = io.WriteString(e.conn, data)
	if err != nil {
		e.conn.Close()
		e.conn = nil
		return fmt.Errorf("siem write: %w", err)
	}
	return nil
}

// dial establishes a new connection to the SIEM endpoint.
func (e *Exporter) dial() (net.Conn, error) {
	if e.cfg.UseTLS {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: e.cfg.SkipVerify,
			ServerName:         e.cfg.Hostname,
		}
		dialer := &net.Dialer{Timeout: e.cfg.Timeout}
		return tls.DialWithDialer(dialer, "tcp", e.cfg.Endpoint, tlsCfg)
	}
	return net.DialTimeout("tcp", e.cfg.Endpoint, e.cfg.Timeout)
}

// Export queues an event for SIEM export. Non-blocking: if the buffer is full,
// the event is dropped. Only block/challenge events are exported; pass events
// are silently filtered.
func (e *Exporter) Export(ev engine.Event) {
	if e == nil {
		return
	}
	if ev.Action != engine.ActionBlock && ev.Action != engine.ActionChallenge {
		return
	}
	e.eventsQueued.Add(1)
	select {
	case e.ch <- ev:
	default:
		e.eventsQueued.Add(-1)
		e.dropped.Add(1)
	}
}

// Stats returns bounded operational counters.
func (e *Exporter) Stats() ExporterStats {
	return ExporterStats{
		Sent:         e.sent.Load(),
		Failed:       e.failed.Load(),
		Dropped:      e.dropped.Load(),
		Connects:     e.connects.Load(),
		EventsQueued: e.eventsQueued.Load(),
	}
}

// Close shuts down the exporter, flushing any pending events.
func (e *Exporter) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	e.mu.Unlock()

	close(e.ch)
	e.wg.Wait()
	return nil
}

// ExporterConfigFromSIEM converts a config.SIEMConfig to an ExporterConfig.
func ExporterConfigFromSIEM(cfg config.SIEMConfig) ExporterConfig {
	return ExporterConfig{
		Endpoint:      cfg.Endpoint,
		Format:        cfg.Format,
		FlushInterval: cfg.FlushInterval,
		BatchSize:     cfg.BatchSize,
		Timeout:       cfg.Timeout,
		SkipVerify:    cfg.SkipVerify,
		ExtraFields:   cfg.Fields,
		UseTLS:        strings.HasPrefix(cfg.Endpoint, "tls://"),
	}
}

// formatJSON renders an event as a compact JSON string for SIEM ingestion.
func formatJSON(ev engine.Event) string {
	// Simple JSON encoding without external deps.
	var sb strings.Builder
	sb.WriteString(`{"timestamp":"`)
	sb.WriteString(ev.Timestamp.UTC().Format(time.RFC3339Nano))
	sb.WriteString(`","id":"`)
	sb.WriteString(ev.ID)
	sb.WriteString(`","action":"`)
	sb.WriteString(ev.Action.String())
	sb.WriteString(`","score":`)
	sb.WriteString(fmt.Sprintf("%d", ev.Score))
	sb.WriteString(`,"client_ip":"`)
	sb.WriteString(ev.ClientIP)
	sb.WriteString(`","method":"`)
	sb.WriteString(ev.Method)
	sb.WriteString(`","path":"`)
	sb.WriteString(ev.Path)
	sb.WriteString(`","query":"`)
	sb.WriteString(ev.Query)
	sb.WriteString(`","user_agent":"`)
	sb.WriteString(ev.UserAgent)
	sb.WriteString(`","host":"`)
	sb.WriteString(ev.Host)
	sb.WriteString(`","status_code":`)
	sb.WriteString(fmt.Sprintf("%d", ev.StatusCode))
	if ev.TenantID != "" {
		sb.WriteString(`,"tenant_id":"`)
		sb.WriteString(ev.TenantID)
		sb.WriteString(`"`)
	}
	if len(ev.Findings) > 0 {
		sb.WriteString(`,"detector":"`)
		sb.WriteString(ev.Findings[0].DetectorName)
		sb.WriteString(`","description":"`)
		sb.WriteString(ev.Findings[0].Description)
		sb.WriteString(`"`)
	}
	sb.WriteString(`}`)
	return sb.String()
}

// version is the SIEM product version (set at link time or build time).
var version = "0.5.0"

// SetVersion allows the application to set the product version at startup.
func SetVersion(v string) {
	version = v
}

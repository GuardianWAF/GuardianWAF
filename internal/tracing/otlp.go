package tracing

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// OTLP exporter defaults. The endpoint is the OTLP/HTTP traces path of a
// collector on the same host, matching the OpenTelemetry SDK default.
const (
	DefaultOTLPEndpoint      = "http://localhost:4318/v1/traces"
	DefaultOTLPTimeout       = 10 * time.Second
	DefaultOTLPBatchSize     = 512
	DefaultOTLPFlushInterval = 5 * time.Second
	DefaultOTLPQueueSize     = 2048

	maxOTLPBatchSize   = 8192
	maxOTLPQueueSize   = 1 << 20
	maxOTLPRetries     = 3
	maxOTLPResponse    = 64 << 10
	otlpRetryBaseDelay = 500 * time.Millisecond
	otlpScopeName      = "github.com/guardianwaf/guardianwaf/internal/tracing"
)

// OTLPConfig configures the OTLP/HTTP JSON exporter. Zero values select the
// Default* constants.
type OTLPConfig struct {
	Endpoint      string            // full traces URL, e.g. https://collector:4318/v1/traces
	Headers       map[string]string // extra request headers, e.g. an Authorization token
	Timeout       time.Duration     // per-request timeout
	BatchSize     int               // spans per request
	FlushInterval time.Duration     // maximum time a span waits in the queue
	QueueSize     int               // spans buffered before new spans are dropped
}

func (c OTLPConfig) withDefaults() OTLPConfig {
	if c.Endpoint == "" {
		c.Endpoint = DefaultOTLPEndpoint
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultOTLPTimeout
	}
	if c.BatchSize == 0 {
		c.BatchSize = DefaultOTLPBatchSize
	}
	if c.FlushInterval == 0 {
		c.FlushInterval = DefaultOTLPFlushInterval
	}
	if c.QueueSize == 0 {
		c.QueueSize = DefaultOTLPQueueSize
	}
	return c
}

// ValidateOTLPConfig rejects endpoints and limits the exporter cannot honor.
// The collector is operator-controlled, so private and loopback hosts are
// allowed; credentials belong in Headers, not in the URL.
func ValidateOTLPConfig(c OTLPConfig) error {
	c = c.withDefaults()
	u, err := url.Parse(c.Endpoint)
	if err != nil {
		return fmt.Errorf("otlp endpoint: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("otlp endpoint must use http or https")
	}
	if u.Hostname() == "" {
		return errors.New("otlp endpoint must include a host")
	}
	if u.User != nil {
		return errors.New("otlp endpoint must not contain credentials; use headers")
	}
	if u.Fragment != "" || u.RawQuery != "" {
		return errors.New("otlp endpoint must not contain a query or fragment")
	}
	for k, v := range c.Headers {
		if !validHeaderName(k) {
			return fmt.Errorf("otlp header %q is not a valid header name", k)
		}
		if strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("otlp header %q contains a control character", k)
		}
	}
	if c.Timeout < 0 || c.FlushInterval < 0 {
		return errors.New("otlp timeout and flush interval must be positive")
	}
	if c.BatchSize < 0 || c.BatchSize > maxOTLPBatchSize {
		return fmt.Errorf("otlp batch size must be between 1 and %d", maxOTLPBatchSize)
	}
	if c.QueueSize < 0 || c.QueueSize > maxOTLPQueueSize {
		return fmt.Errorf("otlp queue size must be between 1 and %d", maxOTLPQueueSize)
	}
	if c.QueueSize < c.BatchSize {
		return errors.New("otlp queue size must be at least the batch size")
	}
	return nil
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := range len(name) {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// otlpSpan is an immutable copy of a finished span, taken on the request path
// so encoding and delivery happen off it.
type otlpSpan struct {
	traceID, spanID, parentID, name string
	kind                            SpanKind
	status                          SpanStatus
	start, end                      time.Time
	attrs                           map[string]string
	events                          []SpanEvent
}

// OTLPExporter batches finished spans and posts them to an OpenTelemetry
// collector using OTLP/HTTP with JSON encoding. Export never blocks: when the
// queue is full the span is dropped and counted.
type OTLPExporter struct {
	cfg         OTLPConfig
	serviceName string
	client      *http.Client
	queue       chan otlpSpan
	stop        chan struct{}
	done        chan struct{}
	stopOnce    sync.Once
	closed      atomic.Bool

	sent    atomic.Int64
	dropped atomic.Int64
	failing atomic.Bool
}

// NewOTLPExporter validates cfg and starts the background sender.
func NewOTLPExporter(cfg OTLPConfig, serviceName string) (*OTLPExporter, error) {
	if err := ValidateOTLPConfig(cfg); err != nil {
		return nil, err
	}
	cfg = cfg.withDefaults()
	if serviceName == "" {
		serviceName = "guardianwaf"
	}
	e := &OTLPExporter{
		cfg:         cfg,
		serviceName: serviceName,
		client:      newOTLPClient(cfg.Timeout),
		queue:       make(chan otlpSpan, cfg.QueueSize),
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
	}
	go e.run()
	return e, nil
}

// newOTLPClient builds a bounded client. Redirects are not followed: a
// collector that redirects is misconfigured, and following would forward the
// configured headers to another origin.
func newOTLPClient(timeout time.Duration) *http.Client {
	transport, _ := http.DefaultTransport.(*http.Transport)
	if transport != nil {
		transport = transport.Clone()
	} else {
		transport = &http.Transport{}
	}
	transport.Proxy = nil
	transport.DialContext = (&net.Dialer{Timeout: min(timeout, 5*time.Second), KeepAlive: 30 * time.Second}).DialContext
	transport.TLSHandshakeTimeout = min(timeout, 5*time.Second)
	transport.ResponseHeaderTimeout = timeout
	transport.ExpectContinueTimeout = time.Second
	transport.IdleConnTimeout = 90 * time.Second
	transport.MaxIdleConnsPerHost = 2
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Export queues a finished span. It is safe for concurrent use.
func (e *OTLPExporter) Export(span *Span) {
	if e.closed.Load() || span == nil {
		return
	}
	span.mu.Lock()
	s := otlpSpan{
		traceID:  span.TraceID,
		spanID:   span.SpanID,
		parentID: span.ParentID,
		name:     span.Name,
		kind:     span.Kind,
		status:   span.Status,
		start:    span.StartTime,
		end:      span.EndTime,
		attrs:    span.Attributes, // immutable once the span has ended
		events:   span.Events,
	}
	span.mu.Unlock()
	if s.end.IsZero() {
		s.end = time.Now()
	}
	select {
	case e.queue <- s:
	default:
		e.dropped.Add(1)
	}
}

// Shutdown flushes queued spans (bounded by the request timeout) and stops
// the sender. Spans exported afterwards are discarded.
func (e *OTLPExporter) Shutdown() {
	e.stopOnce.Do(func() {
		e.closed.Store(true)
		close(e.stop)
	})
	<-e.done
}

// Sent returns the number of spans the collector accepted.
func (e *OTLPExporter) Sent() int64 { return e.sent.Load() }

// Dropped returns the number of spans discarded because the queue was full,
// the collector rejected them, or delivery kept failing.
func (e *OTLPExporter) Dropped() int64 { return e.dropped.Load() }

func (e *OTLPExporter) run() {
	defer close(e.done)
	ticker := time.NewTicker(e.cfg.FlushInterval)
	defer ticker.Stop()
	batch := make([]otlpSpan, 0, e.cfg.BatchSize)
	flush := func(ctx context.Context) {
		if len(batch) > 0 {
			e.send(ctx, batch)
			clear(batch)
			batch = batch[:0]
		}
	}
	for {
		select {
		case s := <-e.queue:
			batch = append(batch, s)
			if len(batch) >= e.cfg.BatchSize {
				flush(context.Background())
			}
		case <-ticker.C:
			flush(context.Background())
		case <-e.stop:
			// Drain what is already queued with one overall deadline so a dead
			// collector cannot stall shutdown.
			ctx, cancel := context.WithTimeout(context.Background(), e.cfg.Timeout)
			defer cancel()
			for {
				select {
				case s := <-e.queue:
					batch = append(batch, s)
					if len(batch) >= e.cfg.BatchSize {
						flush(ctx)
					}
				default:
					flush(ctx)
					return
				}
			}
		}
	}
}

// send delivers one batch, retrying transient failures. The batch is dropped
// (and counted) when it cannot be delivered.
func (e *OTLPExporter) send(ctx context.Context, batch []otlpSpan) {
	body, err := json.Marshal(encodeOTLP(e.serviceName, batch))
	if err != nil {
		e.fail(len(batch), fmt.Errorf("encode: %w", err))
		return
	}
	var lastErr error
	for attempt := range maxOTLPRetries {
		if attempt > 0 {
			delay := otlpRetryBaseDelay << (attempt - 1)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				e.fail(len(batch), ctx.Err())
				return
			case <-e.stop:
				// Shutting down: stop backing off but make one final attempt
				// under the shutdown deadline below.
			}
		}
		retry, err := e.post(ctx, body)
		if err == nil {
			e.sent.Add(int64(len(batch)))
			if e.failing.Swap(false) {
				slog.Default().Info("otlp trace export recovered", "endpoint", e.cfg.Endpoint)
			}
			return
		}
		lastErr = err
		if !retry || ctx.Err() != nil {
			break
		}
	}
	e.fail(len(batch), lastErr)
}

func (e *OTLPExporter) fail(n int, err error) {
	e.dropped.Add(int64(n))
	// Log on the transition only, so an unreachable collector does not flood
	// the application log.
	if !e.failing.Swap(true) {
		slog.Default().Warn("otlp trace export failing; spans are being dropped",
			"endpoint", e.cfg.Endpoint, "error", err)
	}
}

// post sends one request. retry reports whether the failure is transient.
func (e *OTLPExporter) post(ctx context.Context, body []byte) (retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	for k, v := range e.cfg.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "guardianwaf-otlp")
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return true, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxOTLPResponse))
	_ = resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false, nil
	case resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode == http.StatusBadGateway,
		resp.StatusCode == http.StatusServiceUnavailable, resp.StatusCode == http.StatusGatewayTimeout:
		return true, fmt.Errorf("collector returned %s", resp.Status)
	default:
		return false, fmt.Errorf("collector returned %s", resp.Status)
	}
}

// OTLP/JSON wire types (opentelemetry-proto, JSON mapping). 64-bit integers
// are encoded as decimal strings and IDs as lowercase hex, as the spec requires.
type otlpTraceRequest struct {
	ResourceSpans []otlpResourceSpans `json:"resourceSpans"`
}

type otlpResourceSpans struct {
	Resource   otlpResource     `json:"resource"`
	ScopeSpans []otlpScopeSpans `json:"scopeSpans"`
}

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes"`
}

type otlpScopeSpans struct {
	Scope otlpScope      `json:"scope"`
	Spans []otlpWireSpan `json:"spans"`
}

type otlpScope struct {
	Name string `json:"name"`
}

type otlpWireSpan struct {
	TraceID           string          `json:"traceId"`
	SpanID            string          `json:"spanId"`
	ParentSpanID      string          `json:"parentSpanId,omitempty"`
	Name              string          `json:"name"`
	Kind              int             `json:"kind"`
	StartTimeUnixNano string          `json:"startTimeUnixNano"`
	EndTimeUnixNano   string          `json:"endTimeUnixNano"`
	Attributes        []otlpKeyValue  `json:"attributes,omitempty"`
	Events            []otlpWireEvent `json:"events,omitempty"`
	Status            otlpStatus      `json:"status"`
}

type otlpWireEvent struct {
	TimeUnixNano string         `json:"timeUnixNano"`
	Name         string         `json:"name"`
	Attributes   []otlpKeyValue `json:"attributes,omitempty"`
}

type otlpStatus struct {
	Code int `json:"code,omitempty"`
}

type otlpKeyValue struct {
	Key   string        `json:"key"`
	Value otlpAnyString `json:"value"`
}

type otlpAnyString struct {
	StringValue string `json:"stringValue"`
}

func encodeOTLP(serviceName string, batch []otlpSpan) otlpTraceRequest {
	spans := make([]otlpWireSpan, len(batch))
	for i, s := range batch {
		spans[i] = otlpWireSpan{
			TraceID:           s.traceID,
			SpanID:            s.spanID,
			ParentSpanID:      s.parentID,
			Name:              s.name,
			Kind:              otlpKind(s.kind),
			StartTimeUnixNano: unixNano(s.start),
			EndTimeUnixNano:   unixNano(s.end),
			Attributes:        otlpAttributes(s.attrs, "service.name"),
			Status:            otlpStatus{Code: int(s.status)},
		}
		for _, ev := range s.events {
			spans[i].Events = append(spans[i].Events, otlpWireEvent{
				TimeUnixNano: unixNano(ev.Timestamp),
				Name:         ev.Name,
				Attributes:   otlpAttributes(ev.Attributes, ""),
			})
		}
	}
	return otlpTraceRequest{ResourceSpans: []otlpResourceSpans{{
		Resource: otlpResource{Attributes: []otlpKeyValue{
			{Key: "service.name", Value: otlpAnyString{StringValue: serviceName}},
		}},
		ScopeSpans: []otlpScopeSpans{{Scope: otlpScope{Name: otlpScopeName}, Spans: spans}},
	}}}
}

// otlpAttributes converts attributes in sorted key order, omitting skip (the
// service name is carried once on the resource instead of on every span).
func otlpAttributes(attrs map[string]string, skip string) []otlpKeyValue {
	if len(attrs) == 0 {
		return nil
	}
	out := make([]otlpKeyValue, 0, len(attrs))
	for k, v := range attrs {
		if k != skip {
			out = append(out, otlpKeyValue{Key: k, Value: otlpAnyString{StringValue: v}})
		}
	}
	slices.SortFunc(out, func(a, b otlpKeyValue) int { return cmp.Compare(a.Key, b.Key) })
	return out
}

// otlpKind maps SpanKind to the OTLP enum, where 0 is UNSPECIFIED.
func otlpKind(k SpanKind) int {
	if k < SpanKindInternal || k > SpanKindConsumer {
		return 1
	}
	return int(k) + 1
}

func unixNano(t time.Time) string {
	if t.IsZero() {
		return "0"
	}
	return strconv.FormatInt(t.UnixNano(), 10)
}

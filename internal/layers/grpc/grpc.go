// Package grpc provides gRPC proxy and reflection support for GuardianWAF.
package grpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// gRPC constants
const (
	// Content-Type values
	ContentTypeGRPC         = "application/grpc"
	ContentTypeGRPCWeb      = "application/grpc-web"
	ContentTypeGRPCWebText  = "application/grpc-web-text"
	ContentTypeProto        = "application/x-protobuf"

	// gRPC headers
	HeaderGRPCStatus        = "grpc-status"
	HeaderGRPCMessage       = "grpc-message"
	HeaderGRPCStatusDetails = "grpc-status-details-bin"
	HeaderTimeout           = "grpc-timeout"
	HeaderMessageType       = "grpc-message-type"
	HeaderEncoding          = "grpc-encoding"
	HeaderAcceptEncoding    = "grpc-accept-encoding"

	// HTTP/2 pseudo-headers
	HeaderAuthority = ":authority"
	HeaderMethod    = ":method"
	HeaderPath      = ":path"
	HeaderScheme    = ":scheme"

	// Frame types
	FrameData         = 0x00
	FrameHeaders      = 0x01
	FramePriority     = 0x02
	FrameRSTStream    = 0x03
	FrameSettings     = 0x04
	FramePushPromise  = 0x05
	FramePing         = 0x06
	FrameGoAway       = 0x07
	FrameWindowUpdate = 0x08
	FrameContinuation = 0x09

	// gRPC status codes
	StatusOK                 = 0
	StatusCancelled          = 1
	StatusUnknown            = 2
	StatusInvalidArgument    = 3
	StatusDeadlineExceeded   = 4
	StatusNotFound           = 5
	StatusAlreadyExists      = 6
	StatusPermissionDenied   = 7
	StatusResourceExhausted  = 8
	StatusFailedPrecondition = 9
	StatusAborted            = 10
	StatusOutOfRange         = 11
	StatusUnimplemented      = 12
	StatusInternal           = 13
	StatusUnavailable        = 14
	StatusDataLoss           = 15
	StatusUnauthenticated    = 16
)

// Frame represents an HTTP/2 frame.
type Frame struct {
	Type     uint8
	Flags    uint8
	StreamID uint32
	Payload  []byte
}

// IsHeaders checks if this is a HEADERS frame.
func (f *Frame) IsHeaders() bool {
	return f.Type == FrameHeaders
}

// IsData checks if this is a DATA frame.
func (f *Frame) IsData() bool {
	return f.Type == FrameData
}

// IsEndStream checks if END_STREAM flag is set.
func (f *Frame) IsEndStream() bool {
	return f.Flags&0x01 != 0
}

// IsEndHeaders checks if END_HEADERS flag is set.
func (f *Frame) IsEndHeaders() bool {
	return f.Flags&0x04 != 0
}

// RequestInfo contains parsed gRPC request information.
type RequestInfo struct {
	Service        string
	Method         string
	FullMethod     string
	IsStreaming    bool
	ClientStream   bool
	ServerStream   bool
	MessageType    string
	Timeout        time.Duration
	Metadata       map[string]string
	Authority      string
	ContentType    string
}

// Stream tracks an active gRPC stream.
type Stream struct {
	ID           uint32
	Service      string
	Method       string
	StartTime    time.Time
	LastActivity time.Time
	ClientStream bool
	ServerStream bool
	MessagesSent int64
	MessagesRecv int64
	mu           sync.RWMutex
}

// UpdateActivity updates the last activity timestamp.
func (s *Stream) UpdateActivity() {
	s.mu.Lock()
	s.LastActivity = time.Now()
	s.mu.Unlock()
}

// IncMessagesSent increments the sent message count.
func (s *Stream) IncMessagesSent() {
	s.mu.Lock()
	s.MessagesSent++
	s.mu.Unlock()
}

// IncMessagesRecv increments the received message count.
func (s *Stream) IncMessagesRecv() {
	s.mu.Lock()
	s.MessagesRecv++
	s.mu.Unlock()
}

// Security provides gRPC security features.
type Security struct {
	config   *config.GRPCConfig
	streams  map[uint32]*Stream
	streamsMu sync.RWMutex
	methodRateLimiters map[string]*RateLimiter
	rateLimitMu sync.RWMutex
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// RateLimiter implements token bucket rate limiting.
type RateLimiter struct {
	rate   float64
	burst  int
	tokens float64
	last   time.Time
	mu     sync.Mutex
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	return &RateLimiter{
		rate:   rate,
		burst:  burst,
		tokens: float64(burst),
		last:   time.Now(),
	}
}

// Allow checks if a request should be allowed.
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.last).Seconds()
	rl.last = now

	// Add tokens based on elapsed time
	rl.tokens += elapsed * rl.rate
	if rl.tokens > float64(rl.burst) {
		rl.tokens = float64(rl.burst)
	}

	if rl.tokens >= 1 {
		rl.tokens--
		return true
	}
	return false
}

// NewSecurity creates a new gRPC security instance.
func NewSecurity(cfg *config.GRPCConfig) (*Security, error) {
	if cfg == nil {
		cfg = &config.GRPCConfig{}
	}

	s := &Security{
		config:             cfg,
		streams:            make(map[uint32]*Stream),
		methodRateLimiters: make(map[string]*RateLimiter),
		stopCh:             make(chan struct{}),
	}

	// Initialize per-method rate limiters
	for _, rl := range cfg.MethodRateLimits {
		s.methodRateLimiters[rl.Method] = NewRateLimiter(float64(rl.RequestsPerSecond), rl.BurstSize)
	}

	// Start cleanup routine
	s.wg.Add(1)
	go s.cleanupLoop()

	return s, nil
}

// Stop stops the security instance.
func (s *Security) Stop() {
	select {
	case <-s.stopCh:
		return
	default:
		close(s.stopCh)
	}
	s.wg.Wait()
}

// cleanupLoop periodically cleans up stale streams.
func (s *Security) cleanupLoop() {
	defer s.wg.Done()
	defer func() { recover() }()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.cleanupStaleStreams()
		case <-s.stopCh:
			return
		}
	}
}

// cleanupStaleStreams removes stale streams.
func (s *Security) cleanupStaleStreams() {
	if s.config.MaxStreamDuration <= 0 {
		return
	}

	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()

	now := time.Now()
	for id, stream := range s.streams {
		stream.mu.RLock()
		lastActivity := stream.LastActivity
		stream.mu.RUnlock()

		if now.Sub(lastActivity) > s.config.MaxStreamDuration {
			delete(s.streams, id)
		}
	}
}

// IsGRPCRequest checks if this is a gRPC request.
func IsGRPCRequest(r *http.Request) bool {
	contentType := r.Header.Get("Content-Type")
	return strings.HasPrefix(contentType, ContentTypeGRPC) ||
		strings.HasPrefix(contentType, ContentTypeGRPCWeb)
}

// ParseMethod extracts service and method from gRPC path.
// Path format: /service.package.Service/Method
func ParseMethod(path string) (service, method string, err error) {
	if !strings.HasPrefix(path, "/") {
		return "", "", fmt.Errorf("invalid gRPC path: must start with /")
	}

	parts := strings.SplitN(path[1:], "/", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid gRPC path format: %s", path)
	}

	return parts[0], parts[1], nil
}

// IsStreamingMethod checks if the method is streaming based on method name.
// In practice, this would check protobuf definitions. Here we use heuristics.
func IsStreamingMethod(methodName string) (clientStream, serverStream bool) {
	// Common naming conventions for streaming methods
	lowerMethod := strings.ToLower(methodName)
	if strings.Contains(lowerMethod, "stream") {
		return true, true
	}
	if strings.HasPrefix(lowerMethod, "subscribe") ||
		strings.HasPrefix(lowerMethod, "watch") {
		return false, true
	}
	return false, false
}

// GetRateLimiter returns the rate limiter for a method.
func (s *Security) GetRateLimiter(method string) *RateLimiter {
	s.rateLimitMu.RLock()
	if rl, ok := s.methodRateLimiters[method]; ok {
		s.rateLimitMu.RUnlock()
		return rl
	}
	s.rateLimitMu.RUnlock()
	return nil
}

// IsAllowedService checks if a service is allowed.
func (s *Security) IsAllowedService(service string) bool {
	if len(s.config.AllowedServices) == 0 {
		return true
	}
	for _, allowed := range s.config.AllowedServices {
		if allowed == service || allowed == "*" {
			return true
		}
		// Support wildcard patterns
		if strings.HasSuffix(allowed, ".*") {
			prefix := strings.TrimSuffix(allowed, ".*")
			if strings.HasPrefix(service, prefix) {
				return true
			}
		}
	}
	return false
}

// IsBlockedService checks if a service is blocked.
func (s *Security) IsBlockedService(service string) bool {
	for _, blocked := range s.config.BlockedServices {
		if blocked == service {
			return true
		}
		// Support wildcard patterns
		if strings.HasSuffix(blocked, ".*") {
			prefix := strings.TrimSuffix(blocked, ".*")
			if strings.HasPrefix(service, prefix) {
				return true
			}
		}
	}
	return false
}

// IsAllowedMethod checks if a method is allowed.
func (s *Security) IsAllowedMethod(fullMethod string) bool {
	if len(s.config.AllowedMethods) == 0 {
		return true
	}
	for _, allowed := range s.config.AllowedMethods {
		if allowed == fullMethod || allowed == "*" {
			return true
		}
	}
	return false
}

// IsBlockedMethod checks if a method is blocked.
func (s *Security) IsBlockedMethod(fullMethod string) bool {
	for _, blocked := range s.config.BlockedMethods {
		if blocked == fullMethod {
			return true
		}
	}
	return false
}

// RegisterStream registers a new gRPC stream.
func (s *Security) RegisterStream(streamID uint32, service, method string, clientStream, serverStream bool) *Stream {
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()

	// Check max concurrent streams
	if s.config.MaxConcurrentStreams > 0 && len(s.streams) >= s.config.MaxConcurrentStreams {
		return nil
	}

	stream := &Stream{
		ID:           streamID,
		Service:      service,
		Method:       method,
		StartTime:    time.Now(),
		LastActivity: time.Now(),
		ClientStream: clientStream,
		ServerStream: serverStream,
	}
	s.streams[streamID] = stream
	return stream
}

// GetStream retrieves a stream by ID.
func (s *Security) GetStream(streamID uint32) *Stream {
	s.streamsMu.RLock()
	defer s.streamsMu.RUnlock()
	return s.streams[streamID]
}

// UnregisterStream removes a stream.
func (s *Security) UnregisterStream(streamID uint32) {
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()
	delete(s.streams, streamID)
}

// GetAllStreams returns all active streams.
func (s *Security) GetAllStreams() []*Stream {
	s.streamsMu.RLock()
	defer s.streamsMu.RUnlock()

	streams := make([]*Stream, 0, len(s.streams))
	for _, stream := range s.streams {
		streams = append(streams, stream)
	}
	return streams
}

// GetStreamCount returns the total number of active streams.
func (s *Security) GetStreamCount() int {
	s.streamsMu.RLock()
	defer s.streamsMu.RUnlock()
	return len(s.streams)
}

// GetStreamCountForService returns the number of streams for a service.
func (s *Security) GetStreamCountForService(service string) int {
	s.streamsMu.RLock()
	defer s.streamsMu.RUnlock()

	count := 0
	for _, stream := range s.streams {
		if stream.Service == service {
			count++
		}
	}
	return count
}

// ValidateRequest validates a gRPC request.
func (s *Security) ValidateRequest(r *http.Request) error {
	if !s.config.Enabled {
		return nil
	}

	// Check TLS requirement
	if s.config.RequireTLS && r.TLS == nil {
		return fmt.Errorf("TLS required for gRPC")
	}

	// Parse method from path
	service, method, err := ParseMethod(r.URL.Path)
	if err != nil {
		return err
	}

	fullMethod := fmt.Sprintf("%s/%s", service, method)

	// Check service allowlist/blocklist
	if !s.IsAllowedService(service) {
		return fmt.Errorf("service not allowed: %s", service)
	}
	if s.IsBlockedService(service) {
		return fmt.Errorf("service blocked: %s", service)
	}

	// Check method allowlist/blocklist
	if !s.IsAllowedMethod(fullMethod) {
		return fmt.Errorf("method not allowed: %s", fullMethod)
	}
	if s.IsBlockedMethod(fullMethod) {
		return fmt.Errorf("method blocked: %s", fullMethod)
	}

	// Check message size
	if s.config.MaxMessageSize > 0 {
		if r.ContentLength > int64(s.config.MaxMessageSize) {
			return fmt.Errorf("message too large: %d bytes", r.ContentLength)
		}
	}

	// Check rate limit for method
	if rl := s.GetRateLimiter(fullMethod); rl != nil {
		if !rl.Allow() {
			return fmt.Errorf("rate limit exceeded for method: %s", fullMethod)
		}
	}

	return nil
}

// GetRequestInfo extracts request information from HTTP headers.
func GetRequestInfo(r *http.Request) *RequestInfo {
	service, method, _ := ParseMethod(r.URL.Path)
	clientStream, serverStream := IsStreamingMethod(method)

	info := &RequestInfo{
		Service:      service,
		Method:       method,
		FullMethod:   fmt.Sprintf("%s/%s", service, method),
		IsStreaming:  clientStream || serverStream,
		ClientStream: clientStream,
		ServerStream: serverStream,
		MessageType:  r.Header.Get(HeaderMessageType),
		Authority:    r.Header.Get(HeaderAuthority),
		ContentType:  r.Header.Get("Content-Type"),
		Metadata:     make(map[string]string),
	}

	// Parse timeout header
	if timeout := r.Header.Get(HeaderTimeout); timeout != "" {
		// Format: "1H3M" or "5S"
		duration, err := parseGRPCTimeout(timeout)
		if err == nil {
			info.Timeout = duration
		}
	}

	// Extract gRPC metadata (headers starting with grpc-)
	for key, values := range r.Header {
		if strings.HasPrefix(key, "Grpc-") || strings.HasPrefix(key, "grpc-") {
			if len(values) > 0 {
				info.Metadata[key] = values[0]
			}
		}
	}

	return info
}

// parseGRPCTimeout parses gRPC timeout header.
// Format: number followed by unit (H=hour, M=minute, S=second, m=millisecond, u=microsecond, n=nanosecond)
func parseGRPCTimeout(timeout string) (time.Duration, error) {
	if len(timeout) < 2 {
		return 0, fmt.Errorf("invalid timeout format")
	}

	valueStr := timeout[:len(timeout)-1]
	unit := timeout[len(timeout)-1]

	value, err := parseUint(valueStr)
	if err != nil {
		return 0, err
	}

	switch unit {
	case 'H':
		return time.Duration(value) * time.Hour, nil
	case 'M':
		return time.Duration(value) * time.Minute, nil
	case 'S':
		return time.Duration(value) * time.Second, nil
	case 'm':
		return time.Duration(value) * time.Millisecond, nil
	case 'u':
		return time.Duration(value) * time.Microsecond, nil
	case 'n':
		return time.Duration(value) * time.Nanosecond, nil
	default:
		return 0, fmt.Errorf("unknown timeout unit: %c", unit)
	}
}

// parseUint parses an unsigned integer string.
func parseUint(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty value")
	}
	var result int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid digit: %c", c)
		}
		next := result*10 + int64(c-'0')
		if next < result {
			return 0, fmt.Errorf("timeout value overflow")
		}
		result = next
	}
	return result, nil
}

// CreateGRPCErrorResponse creates a gRPC error response.
func CreateGRPCErrorResponse(statusCode int, message string) *http.Response {
	header := make(http.Header)
	header.Set("Content-Type", ContentTypeGRPC)
	header.Set(HeaderGRPCStatus, fmt.Sprintf("%d", statusCode))
	header.Set(HeaderGRPCMessage, encodeGRPCMessage(message))

	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(nil)),
	}
}

// encodeGRPCMessage encodes a message for gRPC headers (percent-encoding).
func encodeGRPCMessage(msg string) string {
	// Simple percent-encoding for non-ASCII characters
	var result strings.Builder
	for _, c := range msg {
		if c >= ' ' && c <= '~' && c != '%' {
			result.WriteRune(c)
		} else {
			result.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return result.String()
}

// IsGRPCWebRequest checks if this is a gRPC-Web request.
func IsGRPCWebRequest(r *http.Request) bool {
	contentType := r.Header.Get("Content-Type")
	return strings.HasPrefix(contentType, ContentTypeGRPCWeb)
}

// Stats holds gRPC statistics.
type Stats struct {
	ActiveStreams    int            `json:"active_streams"`
	TotalStreams     int64          `json:"total_streams"`
	TotalMessages    int64          `json:"total_messages"`
	MessagesByMethod map[string]int64 `json:"messages_by_method"`
	StreamsByService map[string]int   `json:"streams_by_service"`
}

// GetStats returns gRPC statistics.
func (s *Security) GetStats() Stats {
	s.streamsMu.RLock()
	defer s.streamsMu.RUnlock()

	stats := Stats{
		ActiveStreams:    len(s.streams),
		MessagesByMethod: make(map[string]int64),
		StreamsByService: make(map[string]int),
	}

	for _, stream := range s.streams {
		stream.mu.RLock()
		sent := stream.MessagesSent
		recv := stream.MessagesRecv
		stream.mu.RUnlock()

		fullMethod := fmt.Sprintf("%s/%s", stream.Service, stream.Method)
		stats.MessagesByMethod[fullMethod] += sent + recv
		stats.StreamsByService[stream.Service]++
	}

	return stats
}

// ParseHTTP2FrameHeader parses an HTTP/2 frame header.
func ParseHTTP2FrameHeader(data []byte) (*Frame, error) {
	if len(data) < 9 {
		return nil, fmt.Errorf("frame header too short")
	}

	length := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
	frameType := data[3]
	flags := data[4]
	streamID := binary.BigEndian.Uint32(data[5:9]) & 0x7FFFFFFF

	return &Frame{
		Type:     frameType,
		Flags:    flags,
		StreamID: streamID,
		Payload:  make([]byte, length),
	}, nil
}

// ReadHTTP2Preface reads and validates HTTP/2 connection preface.
func ReadHTTP2Preface(r io.Reader) error {
	preface := make([]byte, 24)
	if _, err := io.ReadFull(r, preface); err != nil {
		return err
	}

	expected := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if !bytes.Equal(preface, expected) {
		return fmt.Errorf("invalid HTTP/2 preface")
	}
	return nil
}

// Context keys for gRPC request context.
type contextKey string

const (
	ContextKeyService contextKey = "grpc-service"
	ContextKeyMethod  contextKey = "grpc-method"
	ContextKeyStream  contextKey = "grpc-stream"
)

// GetServiceFromContext retrieves service from context.
func GetServiceFromContext(ctx context.Context) string {
	if val, ok := ctx.Value(ContextKeyService).(string); ok {
		return val
	}
	return ""
}

// GetMethodFromContext retrieves method from context.
func GetMethodFromContext(ctx context.Context) string {
	if val, ok := ctx.Value(ContextKeyMethod).(string); ok {
		return val
	}
	return ""
}

// GetStreamFromContext retrieves stream from context.
func GetStreamFromContext(ctx context.Context) *Stream {
	if val, ok := ctx.Value(ContextKeyStream).(*Stream); ok {
		return val
	}
	return nil
}

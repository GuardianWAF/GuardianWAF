// Package grpc provides gRPC and gRPC-Web proxy support with Protocol Buffer validation.
// This integrates with the existing proxy infrastructure.
package grpc

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Content-Type constants for gRPC detection
const (
	ContentTypeGRPC    = "application/grpc"
	ContentTypeGRPCWeb = "application/grpc-web"
	ContentTypeProto   = "application/x-protobuf"
)

// IsGRPCRequest checks if the request is a gRPC or gRPC-Web request.
func IsGRPCRequest(r *http.Request) bool {
	contentType := r.Header.Get("Content-Type")
	return strings.HasPrefix(contentType, ContentTypeGRPC) ||
		strings.HasPrefix(contentType, ContentTypeGRPCWeb)
}

// IsGRPCWeb checks if the request is gRPC-Web (for browser clients).
func IsGRPCWeb(r *http.Request) bool {
	contentType := r.Header.Get("Content-Type")
	return strings.HasPrefix(contentType, ContentTypeGRPCWeb)
}

// Proxy handles gRPC and gRPC-Web requests with optional protobuf validation.
type Proxy struct {
	// Upstream HTTP/2 transport for gRPC
	transport http.RoundTripper

	// Validator for protobuf messages (optional)
	validator *Validator

	// gRPC-Web support
	grpcWebEnabled bool

	// Maximum message size in bytes
	maxMsgSize int

	// Method-level access control
	methodACL map[string]bool // method name -> allowed

	// Stats
	mu           sync.RWMutex
	rpcCount     uint64
	rpcErrors    uint64
	bytesIn      uint64
	bytesOut     uint64
}

// Config for gRPC proxy.
type Config struct {
	Enabled        bool              `yaml:"enabled"`
	GRPCWebEnabled bool              `yaml:"grpc_web_enabled"`
	ProtoPaths     []string          `yaml:"proto_paths"`      // Paths to .proto files
	AllowedMethods []string          `yaml:"allowed_methods"`  // Methods to allow (empty = all)
	BlockedMethods []string          `yaml:"blocked_methods"`  // Methods to block
	ValidateProto  bool              `yaml:"validate_proto"`   // Validate protobuf messages
	MaxMessageSize int               `yaml:"max_message_size"` // Default: 4MB
	Compression    CompressionConfig `yaml:"compression"`
}

// CompressionConfig controls compression support.
type CompressionConfig struct {
	Enabled         bool     `yaml:"enabled"`
	AllowedEncodings []string `yaml:"allowed_encodings"` // gzip, deflate, identity
}

// DefaultConfig returns default gRPC configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:        false,
		GRPCWebEnabled: true,
		ValidateProto:  true,
		MaxMessageSize: 4 * 1024 * 1024, // 4MB
		Compression: CompressionConfig{
			Enabled:         true,
			AllowedEncodings: []string{"gzip", "identity"},
		},
	}
}

// NewProxy creates a new gRPC proxy.
func NewProxy(cfg *Config) (*Proxy, error) {
	if cfg.MaxMessageSize == 0 {
		cfg.MaxMessageSize = 4 * 1024 * 1024
	}

	p := &Proxy{
		grpcWebEnabled: cfg.GRPCWebEnabled,
		maxMsgSize:     cfg.MaxMessageSize,
		methodACL:      make(map[string]bool),
	}

	// Build HTTP/2 transport for gRPC
	p.transport = &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:  10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	// Initialize validator if enabled
	if cfg.ValidateProto && len(cfg.ProtoPaths) > 0 {
		validator, err := NewValidator(cfg.ProtoPaths)
		if err != nil {
			return nil, fmt.Errorf("failed to create validator: %w", err)
		}
		p.validator = validator
	}

	// Build method ACL
	if len(cfg.AllowedMethods) > 0 {
		for _, method := range cfg.AllowedMethods {
			p.methodACL[method] = true
		}
	}
	for _, method := range cfg.BlockedMethods {
		p.methodACL[method] = false
	}

	return p, nil
}

// CanHandle checks if this proxy can handle the request.
func (p *Proxy) CanHandle(r *http.Request) bool {
	return IsGRPCRequest(r)
}

// ServeHTTP handles gRPC/gRPC-Web requests.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request, targetURL string) {
	if IsGRPCWeb(r) {
		p.handleGRPCWeb(w, r, targetURL)
	} else {
		p.handleGRPC(w, r, targetURL)
	}
}

// handleGRPC handles native gRPC requests.
func (p *Proxy) handleGRPC(w http.ResponseWriter, r *http.Request, targetURL string) {
	// Extract method name from path (e.g., /package.service/method)
	methodName := extractMethodName(r.URL.Path)

	// Check ACL
	if !p.isMethodAllowed(methodName) {
		writeGRPCError(w, http.StatusForbidden, "Method not allowed")
		p.recordError()
		return
	}

	// Validate request if validator is configured
	if p.validator != nil {
		if err := p.validateGRPCRequest(r); err != nil {
			writeGRPCError(w, http.StatusBadRequest, fmt.Sprintf("Validation failed: %v", err))
			p.recordError()
			return
		}
	}

	// Build upstream request
	upstreamReq, err := p.buildUpstreamRequest(r, targetURL)
	if err != nil {
		writeGRPCError(w, http.StatusInternalServerError, "Failed to build request")
		p.recordError()
		return
	}

	// Forward to upstream
	resp, err := p.transport.RoundTrip(upstreamReq)
	if err != nil {
		writeGRPCError(w, http.StatusBadGateway, "Upstream error")
		p.recordError()
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	n, _ := io.Copy(w, resp.Body)
	p.recordTraffic(int64(n), 0)
}

// handleGRPCWeb handles gRPC-Web requests (from browsers).
func (p *Proxy) handleGRPCWeb(w http.ResponseWriter, r *http.Request, targetURL string) {
	// gRPC-Web uses HTTP/1.1 and needs framing conversion
	// Convert gRPC-Web framing to native gRPC framing

	// For now, proxy as-is (full implementation would reframe messages)
	p.handleGRPC(w, r, targetURL)
}

// isMethodAllowed checks if a gRPC method is allowed.
func (p *Proxy) isMethodAllowed(method string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// If no whitelist defined, allow all (except blocked)
	if len(p.methodACL) == 0 {
		return true
	}

	// Check explicit allow/deny
	allowed, exists := p.methodACL[method]
	if exists {
		return allowed
	}

	// Default: deny if whitelist exists, allow otherwise
	return false
}

// validateGRPCRequest validates the gRPC request body.
func (p *Proxy) validateGRPCRequest(r *http.Request) error {
	if p.validator == nil {
		return nil
	}

	// Read and parse gRPC frames (capped at MaxMessageSize)
	maxSize := 4 * 1024 * 1024
	if p.maxMsgSize > 0 {
		maxSize = p.maxMsgSize
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(maxSize)+1))
	if err != nil {
		return fmt.Errorf("failed to read body: %w", err)
	}
	if len(body) > maxSize {
		return fmt.Errorf("request body exceeds maximum size (%d bytes)", maxSize)
	}
	if err != nil {
		return fmt.Errorf("failed to read body: %w", err)
	}
	r.Body.Close()

	// Parse gRPC length-prefixed messages
	messages, err := parseGRPCFrames(body)
	if err != nil {
		return fmt.Errorf("failed to parse frames: %w", err)
	}

	// Validate each message against protobuf schema
	methodName := extractMethodName(r.URL.Path)
	for _, msg := range messages {
		if err := p.validator.ValidateMessage(methodName, msg); err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
	}

	// Restore body for upstream
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	return nil
}

// buildUpstreamRequest creates the upstream gRPC request.
func (p *Proxy) buildUpstreamRequest(r *http.Request, targetURL string) (*http.Request, error) {
	// Clone request (capped at max message size)
	maxSize := 4 * 1024 * 1024
	if p.maxMsgSize > 0 {
		maxSize = p.maxMsgSize
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(maxSize)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxSize {
		return nil, fmt.Errorf("request body exceeds maximum size (%d bytes)", maxSize)
	}
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Create new URL
	url := targetURL + r.URL.Path
	if r.URL.RawQuery != "" {
		url = url + "?" + r.URL.RawQuery
	}

	ctx := r.Context()
	upstreamReq, err := http.NewRequestWithContext(ctx, r.Method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	// Copy headers
	copyHeaders(upstreamReq.Header, r.Header)

	// Ensure HTTP/2
	upstreamReq.Proto = "HTTP/2"
	upstreamReq.ProtoMajor = 2
	upstreamReq.ProtoMinor = 0

	return upstreamReq, nil
}

// extractMethodName extracts the gRPC method name from the path.
func extractMethodName(path string) string {
	// Path format: /package.service/method
	parts := strings.Split(path, "/")
	if len(parts) >= 3 {
		return parts[len(parts)-1]
	}
	return path
}

// parseGRPCFrames parses gRPC length-prefixed message frames.
func parseGRPCFrames(data []byte) ([][]byte, error) {
	var messages [][]byte
	offset := 0

	for offset < len(data) {
		if offset+5 > len(data) {
			break // Incomplete frame
		}

		// First byte: compression flag (0 = none, 1 = gzip)
		compressed := data[offset] == 1
		offset++

		// Next 4 bytes: message length (big-endian)
		length := binary.BigEndian.Uint32(data[offset:])
		offset += 4

		if offset+int(length) > len(data) {
			return nil, fmt.Errorf("incomplete message: expected %d bytes, got %d", length, len(data)-offset)
		}

		message := data[offset : offset+int(length)]

		// Decompress if needed
		if compressed {
			decompressed, err := decompressGzip(message)
			if err != nil {
				return nil, fmt.Errorf("failed to decompress: %w", err)
			}
			message = decompressed
		}

		messages = append(messages, message)
		offset += int(length)
	}

	return messages, nil
}

// decompressGzip decompresses gzip data with a size limit to prevent decompression bombs.
func decompressGzip(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	const maxDecompressedSize = 16 * 1024 * 1024 // 16MB limit
	limited := io.LimitReader(reader, maxDecompressedSize+1)
	result, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(result) > maxDecompressedSize {
		return nil, fmt.Errorf("decompressed gRPC message exceeds %d bytes", maxDecompressedSize)
	}
	return result, nil
}

// hopByHopHeaders are headers that should not be forwarded by proxies (RFC 7230 Section 6.1).
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// copyHeaders copies headers from src to dst, skipping hop-by-hop headers.
func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		if hopByHopHeaders[k] {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// writeGRPCError writes a gRPC error response.
func writeGRPCError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", ContentTypeGRPC)
	w.Header().Set("grpc-status", fmt.Sprintf("%d", code))
	w.Header().Set("grpc-message", message)
	w.WriteHeader(http.StatusOK) // gRPC always returns 200 OK with trailers
	_, _ = w.Write([]byte{})    // Empty body - error ignored (client disconnect)
}

// recordError records an RPC error.
func (p *Proxy) recordError() {
	p.mu.Lock()
	p.rpcErrors++
	p.mu.Unlock()
}

// recordTraffic records traffic stats.
func (p *Proxy) recordTraffic(bytesOut, bytesIn int64) {
	p.mu.Lock()
	p.rpcCount++
	p.bytesOut += uint64(bytesOut)
	p.bytesIn += uint64(bytesIn)
	p.mu.Unlock()
}

// Stats returns proxy statistics.
func (p *Proxy) Stats() Stats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return Stats{
		RPCCount:  p.rpcCount,
		RPCErrors: p.rpcErrors,
		BytesIn:   p.bytesIn,
		BytesOut:  p.bytesOut,
	}
}

// Stats contains gRPC proxy statistics.
type Stats struct {
	RPCCount  uint64 `json:"rpc_count"`
	RPCErrors uint64 `json:"rpc_errors"`
	BytesIn   uint64 `json:"bytes_in"`
	BytesOut  uint64 `json:"bytes_out"`
}

// Validator provides protobuf message validation.
type Validator struct {
	mu          sync.RWMutex
	protoFiles  []string
	messageTypes map[string]*MessageType
}

// MessageType represents a protobuf message type.
type MessageType struct {
	Name       string
	Fields     []Field
	Required   []string
	Constraints map[string]Constraint
}

// Field represents a protobuf field.
type Field struct {
	Name     string
	Number   int
	Type     string
	Required bool
	Repeated bool
}

// Constraint represents validation constraints for a field.
type Constraint struct {
	MinLen   *int
	MaxLen   *int
	Pattern  *string
	MinVal   *float64
	MaxVal   *float64
}

// NewValidator creates a new protobuf validator.
func NewValidator(protoPaths []string) (*Validator, error) {
	v := &Validator{
		protoFiles:   protoPaths,
		messageTypes: make(map[string]*MessageType),
	}

	// In a full implementation, this would parse .proto files
	// For now, we use a simplified approach

	return v, nil
}

// ValidateMessage validates a protobuf message.
func (v *Validator) ValidateMessage(methodName string, data []byte) error {
	// Simplified validation - in production this would decode the protobuf
	// and validate against the schema

	if len(data) == 0 {
		return fmt.Errorf("empty message")
	}

	// Check max size (4MB default)
	if len(data) > 4*1024*1024 {
		return fmt.Errorf("message too large: %d bytes", len(data))
	}

	return nil
}

// RegisterMessageType registers a message type for validation.
func (v *Validator) RegisterMessageType(name string, msgType *MessageType) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.messageTypes[name] = msgType
}

// GetMessageType returns a registered message type.
func (v *Validator) GetMessageType(name string) *MessageType {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.messageTypes[name]
}

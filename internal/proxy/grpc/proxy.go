// Package grpc provides gRPC and gRPC-Web proxy support with Protocol Buffer validation.
// This integrates with the existing proxy infrastructure.
package grpc

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"math"
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
	n, err := io.Copy(w, resp.Body)
	if err != nil {
		p.recordError()
	}
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
	// Sanitize message to prevent CRLF/header injection
	safe := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return ' '
		}
		return r
	}, message)
	w.Header().Set("grpc-message", safe)
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

// Protobuf wire type constants.
const (
	wireVarint     = 0
	wireFixed64    = 1
	wireBytes      = 2
	wireStartGroup = 3 // deprecated
	wireEndGroup   = 4 // deprecated
	wireFixed32    = 5
)

// Protobuf field type strings (for schema-based validation).
const (
	FieldTypeDouble   = "double"
	FieldTypeFloat    = "float"
	FieldTypeInt64    = "int64"
	FieldTypeUint64   = "uint64"
	FieldTypeInt32    = "int32"
	FieldTypeFixed64  = "fixed64"
	FieldTypeFixed32  = "fixed32"
	FieldTypeBool     = "bool"
	FieldTypeString   = "string"
	FieldTypeBytes    = "bytes"
	FieldTypeUint32   = "uint32"
	FieldTypeSfixed32 = "sfixed32"
	FieldTypeSfixed64 = "sfixed64"
	FieldTypeSint32   = "sint32"
	FieldTypeSint64   = "sint64"
	FieldTypeMessage  = "message"
	FieldTypeEnum     = "enum"
)

// Structural limits for protobuf validation.
const (
	maxFieldCount      = 10000
	maxNestedDepth     = 16
	maxRepeatedItems   = 10000
	maxStringLen       = 4 * 1024 * 1024 // 4MB per string field
	maxBytesLen        = 4 * 1024 * 1024 // 4MB per bytes field
	maxVarintBytes     = 10              // protobuf varints are at most 10 bytes
)

// Validator provides protobuf message validation with wire format decoding.
type Validator struct {
	mu           sync.RWMutex
	protoPaths   []string
	messageTypes map[string]*MessageType
}

// MessageType represents a protobuf message type schema.
type MessageType struct {
	Name        string
	Fields      []Field
	Required    []string
	Constraints map[string]Constraint
}

// Field represents a protobuf field in a message schema.
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

// decodedField holds a decoded protobuf field from wire format.
type decodedField struct {
	FieldNumber int
	WireType    int
	Value       []byte // raw value bytes
	Varint      uint64 // decoded varint (wire types 0)
}

// ValidationResult contains detailed results from protobuf validation.
type ValidationResult struct {
	FieldCount     int
	Fields         []decodedField
	UnknownFields  []int
	MissingFields  []string
	Violations     []string
	Warnings       []string
}

// NewValidator creates a new protobuf validator.
func NewValidator(protoPaths []string) (*Validator, error) {
	v := &Validator{
		protoPaths:   protoPaths,
		messageTypes: make(map[string]*MessageType),
	}
	return v, nil
}

// ValidateMessage validates a protobuf message against wire format rules
// and optionally against a registered schema for the given method.
func (v *Validator) ValidateMessage(methodName string, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty message")
	}
	if len(data) > 4*1024*1024 {
		return fmt.Errorf("message too large: %d bytes", len(data))
	}

	result := v.ValidateMessageDetailed(methodName, data, 0)
	if len(result.Violations) > 0 {
		return fmt.Errorf("%s", result.Violations[0])
	}
	return nil
}

// ValidateMessageDetailed performs full protobuf wire format validation
// and returns structured results including warnings.
func (v *Validator) ValidateMessageDetailed(methodName string, data []byte, depth int) ValidationResult {
	result := ValidationResult{}

	if depth >= maxNestedDepth {
		result.Violations = append(result.Violations, "message nesting exceeds maximum depth")
		return result
	}

	// Decode wire format
	fields, err := decodeWireFormat(data)
	if err != nil {
		result.Violations = append(result.Violations, fmt.Sprintf("wire format error: %v", err))
		return result
	}

	result.Fields = fields
	result.FieldCount = len(fields)

	// Structural limits
	if len(fields) > maxFieldCount {
		result.Violations = append(result.Violations, fmt.Sprintf("too many fields: %d (max %d)", len(fields), maxFieldCount))
		return result
	}

	// Look up registered schema
	v.mu.RLock()
	schema := v.messageTypes[methodName]
	v.mu.RUnlock()

	if schema != nil {
		v.validateAgainstSchema(schema, fields, depth, &result)
	} else {
		// No schema registered — validate wire format integrity only
		v.validateWireIntegrity(fields, depth, &result)
	}

	return result
}

// validateAgainstSchema validates decoded fields against a registered message schema.
func (v *Validator) validateAgainstSchema(schema *MessageType, fields []decodedField, depth int, result *ValidationResult) {
	// Build field number -> schema lookup
	schemaByNumber := make(map[int]*Field)
	schemaByName := make(map[string]*Field)
	for i := range schema.Fields {
		f := &schema.Fields[i]
		schemaByNumber[f.Number] = f
		schemaByName[f.Name] = f
	}

	// Track which required fields were seen
	seenFields := make(map[int]int) // field number -> count

	for _, df := range fields {
		seenFields[df.FieldNumber]++

		sf, known := schemaByNumber[df.FieldNumber]
		if !known {
			result.UnknownFields = append(result.UnknownFields, df.FieldNumber)
			continue
		}

		// Wire type compatibility check
		if err := checkWireTypeCompat(sf.Type, df.WireType); err != nil {
			result.Violations = append(result.Violations,
				fmt.Sprintf("field %s (#%d): %v", sf.Name, sf.Number, err))
			continue
		}

		// Apply constraints
		if c, ok := schema.Constraints[sf.Name]; ok {
			v.applyConstraint(sf, &c, &df, result)
		}

		// Recurse into embedded messages
		if sf.Type == FieldTypeMessage && df.WireType == wireBytes && len(df.Value) > 0 {
			sub := v.ValidateMessageDetailed(sf.Name, df.Value, depth+1)
			result.Violations = append(result.Violations, sub.Violations...)
			result.Warnings = append(result.Warnings, sub.Warnings...)
		}
	}

	// Check repeated field limits
	for fieldNum, count := range seenFields {
		if sf, ok := schemaByNumber[fieldNum]; ok && sf.Repeated && count > maxRepeatedItems {
			result.Violations = append(result.Violations,
				fmt.Sprintf("field %s: too many repeated items (%d, max %d)", sf.Name, count, maxRepeatedItems))
		}
	}

	// Check required fields
	for _, reqName := range schema.Required {
		sf, ok := schemaByName[reqName]
		if !ok {
			continue
		}
		if _, seen := seenFields[sf.Number]; !seen {
			result.MissingFields = append(result.MissingFields, reqName)
			result.Violations = append(result.Violations,
				fmt.Sprintf("required field missing: %s (#%d)", reqName, sf.Number))
		}
	}
}

// validateWireIntegrity validates decoded fields without a schema.
// Checks wire type consistency, size limits, and structural anomalies.
func (v *Validator) validateWireIntegrity(fields []decodedField, depth int, result *ValidationResult) {
	// Track field numbers for duplicate detection
	seenNumbers := make(map[int]int)

	for _, df := range fields {
		seenNumbers[df.FieldNumber]++

		switch df.WireType {
		case wireVarint:
			// Varint already decoded — no further validation
		case wireFixed64:
			if len(df.Value) != 8 {
				result.Violations = append(result.Violations,
					fmt.Sprintf("field #%d: fixed64 has %d bytes (expected 8)", df.FieldNumber, len(df.Value)))
			}
		case wireFixed32:
			if len(df.Value) != 4 {
				result.Violations = append(result.Violations,
					fmt.Sprintf("field #%d: fixed32 has %d bytes (expected 4)", df.FieldNumber, len(df.Value)))
			}
		case wireBytes:
			if len(df.Value) > maxBytesLen {
				result.Violations = append(result.Violations,
					fmt.Sprintf("field #%d: length-delimited field exceeds %d bytes", df.FieldNumber, maxBytesLen))
			}
			// Attempt recursive decode — if it looks like a valid message, validate it
			if len(df.Value) > 0 && depth < maxNestedDepth {
				subFields, err := decodeWireFormat(df.Value)
				if err == nil && len(subFields) > 0 {
					// Looks like an embedded message — validate recursively
					sub := v.ValidateMessageDetailed(fmt.Sprintf("nested_%d", df.FieldNumber), df.Value, depth+1)
					result.Violations = append(result.Violations, sub.Violations...)
					result.Warnings = append(result.Warnings, sub.Warnings...)
				}
			}
		case wireStartGroup, wireEndGroup:
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("field #%d: deprecated group wire type %d", df.FieldNumber, df.WireType))
		default:
			result.Violations = append(result.Violations,
				fmt.Sprintf("field #%d: unknown wire type %d", df.FieldNumber, df.WireType))
		}
	}

	// Warn on excessive repeated fields
	for num, count := range seenNumbers {
		if count > maxRepeatedItems {
			result.Violations = append(result.Violations,
				fmt.Sprintf("field #%d: %d repeated entries exceeds limit %d", num, count, maxRepeatedItems))
		}
	}
}

// applyConstraint validates a field value against its constraint.
func (v *Validator) applyConstraint(sf *Field, c *Constraint, df *decodedField, result *ValidationResult) {
	switch sf.Type {
	case FieldTypeString, FieldTypeBytes:
		length := len(df.Value)
		if c.MinLen != nil && length < *c.MinLen {
			result.Violations = append(result.Violations,
				fmt.Sprintf("field %s: length %d below minimum %d", sf.Name, length, *c.MinLen))
		}
		if c.MaxLen != nil && length > *c.MaxLen {
			result.Violations = append(result.Violations,
				fmt.Sprintf("field %s: length %d exceeds maximum %d", sf.Name, length, *c.MaxLen))
		}
	case FieldTypeInt32, FieldTypeInt64, FieldTypeSint32, FieldTypeSint64:
		if c.MinVal != nil || c.MaxVal != nil {
			val := int64(df.Varint)
			if c.MinVal != nil && float64(val) < *c.MinVal {
				result.Violations = append(result.Violations,
					fmt.Sprintf("field %s: value %d below minimum %v", sf.Name, val, *c.MinVal))
			}
			if c.MaxVal != nil && float64(val) > *c.MaxVal {
				result.Violations = append(result.Violations,
					fmt.Sprintf("field %s: value %d exceeds maximum %v", sf.Name, val, *c.MaxVal))
			}
		}
	case FieldTypeUint32, FieldTypeUint64:
		if c.MinVal != nil || c.MaxVal != nil {
			val := df.Varint
			if c.MinVal != nil && float64(val) < *c.MinVal {
				result.Violations = append(result.Violations,
					fmt.Sprintf("field %s: value %d below minimum %v", sf.Name, val, *c.MinVal))
			}
			if c.MaxVal != nil && float64(val) > *c.MaxVal {
				result.Violations = append(result.Violations,
					fmt.Sprintf("field %s: value %d exceeds maximum %v", sf.Name, val, *c.MaxVal))
			}
		}
	case FieldTypeDouble, FieldTypeFloat:
		if (c.MinVal != nil || c.MaxVal != nil) && len(df.Value) >= 4 {
			var fval float64
			if sf.Type == FieldTypeDouble && len(df.Value) == 8 {
				fval = float64(math.Float64frombits(binary.LittleEndian.Uint64(df.Value)))
			} else if len(df.Value) == 4 {
				fval = float64(math.Float32frombits(binary.LittleEndian.Uint32(df.Value[:4])))
			}
			if c.MinVal != nil && fval < *c.MinVal {
				result.Violations = append(result.Violations,
					fmt.Sprintf("field %s: value %f below minimum %v", sf.Name, fval, *c.MinVal))
			}
			if c.MaxVal != nil && fval > *c.MaxVal {
				result.Violations = append(result.Violations,
					fmt.Sprintf("field %s: value %f exceeds maximum %v", sf.Name, fval, *c.MaxVal))
			}
		}
	}
}

// checkWireTypeCompat checks if a wire type is compatible with a schema field type.
func checkWireTypeCompat(fieldType string, wireType int) error {
	switch fieldType {
	case FieldTypeInt32, FieldTypeInt64, FieldTypeUint32, FieldTypeUint64,
		FieldTypeSint32, FieldTypeSint64, FieldTypeBool, FieldTypeEnum:
		if wireType != wireVarint {
			return fmt.Errorf("expected varint wire type for %s, got %d", fieldType, wireType)
		}
	case FieldTypeFixed64, FieldTypeSfixed64, FieldTypeDouble:
		if wireType != wireFixed64 {
			return fmt.Errorf("expected fixed64 wire type for %s, got %d", fieldType, wireType)
		}
	case FieldTypeFixed32, FieldTypeSfixed32, FieldTypeFloat:
		if wireType != wireFixed32 {
			return fmt.Errorf("expected fixed32 wire type for %s, got %d", fieldType, wireType)
		}
	case FieldTypeString, FieldTypeBytes, FieldTypeMessage:
		if wireType != wireBytes {
			return fmt.Errorf("expected length-delimited wire type for %s, got %d", fieldType, wireType)
		}
	}
	return nil
}

// decodeWireFormat decodes all fields from protobuf wire format bytes.
func decodeWireFormat(data []byte) ([]decodedField, error) {
	var fields []decodedField
	offset := 0

	for offset < len(data) {
		// Read field tag (varint)
		tag, n, err := decodeVarint(data[offset:])
		if err != nil {
			return fields, fmt.Errorf("offset %d: %w", offset, err)
		}
		if n == 0 {
			return fields, fmt.Errorf("offset %d: zero-length varint", offset)
		}
		offset += n

		fieldNumber := int(tag >> 3)
		wireType := int(tag & 0x07)

		if fieldNumber == 0 {
			return fields, fmt.Errorf("field number 0 is invalid")
		}

		df := decodedField{
			FieldNumber: fieldNumber,
			WireType:    wireType,
		}

		switch wireType {
		case wireVarint:
			val, n, err := decodeVarint(data[offset:])
			if err != nil {
				return fields, fmt.Errorf("field #%d varint: %w", fieldNumber, err)
			}
			df.Varint = val
			offset += n

		case wireFixed64:
			if offset+8 > len(data) {
				return fields, fmt.Errorf("field #%d: incomplete fixed64", fieldNumber)
			}
			df.Value = data[offset : offset+8]
			offset += 8

		case wireBytes:
			length, n, err := decodeVarint(data[offset:])
			if err != nil {
				return fields, fmt.Errorf("field #%d length: %w", fieldNumber, err)
			}
			offset += n
			if offset+int(length) > len(data) {
				return fields, fmt.Errorf("field #%d: declared %d bytes but only %d remain", fieldNumber, length, len(data)-offset)
			}
			df.Value = data[offset : offset+int(length)]
			offset += int(length)

		case wireFixed32:
			if offset+4 > len(data) {
				return fields, fmt.Errorf("field #%d: incomplete fixed32", fieldNumber)
			}
			df.Value = data[offset : offset+4]
			offset += 4

		case wireStartGroup:
			// Groups are deprecated — skip to matching end group
			depth := 1
			for offset < len(data) && depth > 0 {
				skipTag, skipN, err := decodeVarint(data[offset:])
				if err != nil {
					return fields, fmt.Errorf("field #%d group: %w", fieldNumber, err)
				}
				offset += skipN
				skipWT := int(skipTag & 0x07)
				switch skipWT {
				case wireStartGroup:
					depth++
				case wireEndGroup:
					depth--
				case wireVarint:
					_, vn, _ := decodeVarint(data[offset:])
					offset += vn
				case wireFixed64:
					offset += 8
				case wireFixed32:
					offset += 4
				case wireBytes:
					bl, bn, _ := decodeVarint(data[offset:])
					offset += bn + int(bl)
				}
			}

		case wireEndGroup:
			// Should not appear at top level

		default:
			return fields, fmt.Errorf("field #%d: unknown wire type %d", fieldNumber, wireType)
		}

		fields = append(fields, df)
	}

	return fields, nil
}

// decodeVarint decodes a protobuf varint from data, returning the value and bytes consumed.
func decodeVarint(data []byte) (uint64, int, error) {
	var value uint64
	for i := range min(len(data), maxVarintBytes) {
		b := data[i]
		value |= uint64(b&0x7F) << (i * 7)
		if b&0x80 == 0 {
			return value, i + 1, nil
		}
	}
	if len(data) >= maxVarintBytes {
		return 0, 0, fmt.Errorf("varint too long")
	}
	return 0, 0, fmt.Errorf("incomplete varint")
}

// RegisterMessageType registers a message type schema for validation.
func (v *Validator) RegisterMessageType(name string, msgType *MessageType) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.messageTypes[name] = msgType
}

// GetMessageType returns a registered message type schema.
func (v *Validator) GetMessageType(name string) *MessageType {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.messageTypes[name]
}

// RegisterSchema is an alias for RegisterMessageType for convenience.
func (v *Validator) RegisterSchema(name string, msgType *MessageType) {
	v.RegisterMessageType(name, msgType)
}

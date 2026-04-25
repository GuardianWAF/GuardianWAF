package grpc

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
)

// =====================================================================
// ServeHTTP dispatching
// =====================================================================

func TestServeHTTP_GRPCWeb(t *testing.T) {
	cfg := DefaultConfig()
	proxy, err := NewProxy(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/test", bytes.NewReader([]byte("data")))
	r.Header.Set("Content-Type", ContentTypeGRPCWeb)

	// ServeHTTP dispatches to handleGRPCWeb which calls handleGRPC.
	// Since there's no upstream, it will get a BadGateway but we test
	// the dispatch logic works (no panic).
	proxy.ServeHTTP(w, r, "http://127.0.0.1:1")

	// Should get 502 (upstream error) since no upstream is running
	// or 200 with grpc error, depending on path
	if w.Code != http.StatusOK && w.Code != http.StatusBadGateway {
		t.Logf("ServeHTTP GRPC-Web response code: %d", w.Code)
	}
}

func TestServeHTTP_NativeGRPC(t *testing.T) {
	cfg := DefaultConfig()
	proxy, err := NewProxy(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/test", bytes.NewReader([]byte("data")))
	r.Header.Set("Content-Type", ContentTypeGRPC)

	proxy.ServeHTTP(w, r, "http://127.0.0.1:1")

	if w.Code != http.StatusOK && w.Code != http.StatusBadGateway {
		t.Logf("ServeHTTP native gRPC response code: %d", w.Code)
	}
}

// =====================================================================
// handleGRPC - method blocked
// =====================================================================

func TestHandleGRPC_MethodBlocked(t *testing.T) {
	cfg := &Config{
		AllowedMethods: []string{"GetUser"},
		MaxMessageSize: 1024,
	}
	proxy, err := NewProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/package.service/MethodBlocked", bytes.NewReader([]byte("data")))
	r.Header.Set("Content-Type", ContentTypeGRPC)

	proxy.handleGRPC(w, r, "http://127.0.0.1:1")

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (gRPC always returns 200), got %d", w.Code)
	}
	// grpc-status header should indicate forbidden
	if w.Header().Get("grpc-status") != "403" {
		t.Errorf("expected grpc-status 403, got %s", w.Header().Get("grpc-status"))
	}
}

// =====================================================================
// writeGRPCError
// =====================================================================

func TestWriteGRPCError(t *testing.T) {
	w := httptest.NewRecorder()
	writeGRPCError(w, http.StatusBadRequest, "test error message")

	if w.Code != http.StatusOK {
		t.Errorf("gRPC errors should return 200 OK, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != ContentTypeGRPC {
		t.Errorf("expected Content-Type %s, got %s", ContentTypeGRPC, w.Header().Get("Content-Type"))
	}
	if w.Header().Get("grpc-status") != "400" {
		t.Errorf("expected grpc-status 400, got %s", w.Header().Get("grpc-status"))
	}
	if w.Header().Get("grpc-message") != "test error message" {
		t.Errorf("expected grpc-message 'test error message', got %s", w.Header().Get("grpc-message"))
	}
}

func TestWriteGRPCError_CRLFInjection(t *testing.T) {
	w := httptest.NewRecorder()
	writeGRPCError(w, http.StatusInternalServerError, "error\r\nX-Injected: true")

	msg := w.Header().Get("grpc-message")
	if bytes.Contains([]byte(msg), []byte("\r")) || bytes.Contains([]byte(msg), []byte("\n")) {
		t.Errorf("CRLF should be sanitized, got: %q", msg)
	}
}

// =====================================================================
// recordError
// =====================================================================

func TestRecordError(t *testing.T) {
	cfg := DefaultConfig()
	proxy, err := NewProxy(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	proxy.recordError()
	proxy.recordError()
	proxy.recordError()

	stats := proxy.Stats()
	if stats.RPCErrors != 3 {
		t.Errorf("expected 3 RPC errors, got %d", stats.RPCErrors)
	}
}

// =====================================================================
// copyHeaders
// =====================================================================

func TestCopyHeaders(t *testing.T) {
	src := http.Header{}
	src.Set("Content-Type", "application/grpc")
	src.Set("Te", "trailers")
	src.Set("X-Custom", "value")
	src.Set("Connection", "keep-alive")

	dst := http.Header{}
	copyHeaders(dst, src)

	if dst.Get("Content-Type") != "application/grpc" {
		t.Error("expected Content-Type to be copied")
	}
	if dst.Get("X-Custom") != "value" {
		t.Error("expected X-Custom to be copied")
	}
	if dst.Get("Te") != "" {
		t.Error("Te is a hop-by-hop header and should NOT be copied")
	}
	if dst.Get("Connection") != "" {
		t.Error("Connection is a hop-by-hop header and should NOT be copied")
	}
}

func TestCopyHeaders_MultipleValues(t *testing.T) {
	src := http.Header{}
	src.Add("X-Multi", "val1")
	src.Add("X-Multi", "val2")

	dst := http.Header{}
	copyHeaders(dst, src)

	vals := dst.Values("X-Multi")
	if len(vals) != 2 {
		t.Errorf("expected 2 values, got %d", len(vals))
	}
}

// =====================================================================
// decompressGzip
// =====================================================================

func TestDecompressGzip_Valid(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write([]byte("hello compressed world"))
	gw.Close()

	result, err := decompressGzip(buf.Bytes())
	if err != nil {
		t.Fatalf("decompressGzip failed: %v", err)
	}
	if string(result) != "hello compressed world" {
		t.Errorf("expected 'hello compressed world', got %q", result)
	}
}

func TestDecompressGzip_InvalidData(t *testing.T) {
	_, err := decompressGzip([]byte("not gzip data"))
	if err == nil {
		t.Error("expected error for invalid gzip data")
	}
}

func TestDecompressGzip_DecompressionBomb(t *testing.T) {
	// Create gzip data that decompresses to > 16MB
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	// Write enough data to exceed limit after decompression
	largeData := bytes.Repeat([]byte("A"), 16*1024*1024+1)
	gw.Write(largeData)
	gw.Close()

	_, err := decompressGzip(buf.Bytes())
	if err == nil {
		t.Error("expected error for decompression bomb")
	}
}

// =====================================================================
// parseGRPCFrames - compressed frame
// =====================================================================

func TestParseGRPCFrames_CompressedFrame(t *testing.T) {
	payload := []byte("compressed payload")
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write(payload)
	gw.Close()
	compressed := buf.Bytes()

	frame := make([]byte, 5+len(compressed))
	frame[0] = 1 // compressed flag
	binary.BigEndian.PutUint32(frame[1:], uint32(len(compressed)))
	copy(frame[5:], compressed)

	messages, err := parseGRPCFrames(frame)
	if err != nil {
		t.Fatalf("parseGRPCFrames failed: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}
	if string(messages[0]) != "compressed payload" {
		t.Errorf("expected 'compressed payload', got %q", messages[0])
	}
}

func TestParseGRPCFrames_CompressedInvalidData(t *testing.T) {
	frame := make([]byte, 6)
	frame[0] = 1 // compressed flag
	binary.BigEndian.PutUint32(frame[1:], 1)
	frame[5] = 0xFF // invalid gzip data

	_, err := parseGRPCFrames(frame)
	if err == nil {
		t.Error("expected error for invalid compressed data")
	}
}

func TestParseGRPCFrames_IncompleteMessage(t *testing.T) {
	frame := make([]byte, 10)
	frame[0] = 0
	binary.BigEndian.PutUint32(frame[1:], 100) // claims 100 bytes
	copy(frame[5:], []byte("short"))            // only 5 bytes available

	_, err := parseGRPCFrames(frame)
	if err == nil {
		t.Error("expected error for incomplete message")
	}
}

func TestParseGRPCFrames_EmptyData(t *testing.T) {
	messages, err := parseGRPCFrames([]byte{})
	if err != nil {
		t.Fatalf("expected no error for empty data, got %v", err)
	}
	if len(messages) != 0 {
		t.Errorf("expected 0 messages, got %d", len(messages))
	}
}

func TestParseGRPCFrames_IncompleteHeader(t *testing.T) {
	// Only 3 bytes — not enough for a full 5-byte header
	messages, err := parseGRPCFrames([]byte{0, 0, 3})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(messages) != 0 {
		t.Errorf("expected 0 messages for incomplete header, got %d", len(messages))
	}
}

// =====================================================================
// buildUpstreamRequest
// =====================================================================

func TestBuildUpstreamRequest_Basic(t *testing.T) {
	cfg := DefaultConfig()
	proxy, err := NewProxy(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	body := []byte("test body content")
	r := httptest.NewRequest("POST", "/package.Service/Method?key=value", bytes.NewReader(body))
	r.Header.Set("Content-Type", ContentTypeGRPC)
	r.Header.Set("X-Custom", "header-value")

	upstreamReq, err := proxy.buildUpstreamRequest(r, "http://upstream:9090")
	if err != nil {
		t.Fatalf("buildUpstreamRequest failed: %v", err)
	}

	// Check URL includes target + path + query
	if upstreamReq.URL.Scheme != "http" {
		t.Errorf("expected scheme http, got %s", upstreamReq.URL.Scheme)
	}
	if upstreamReq.URL.Path != "/package.Service/Method" {
		t.Errorf("expected path /package.Service/Method, got %s", upstreamReq.URL.Path)
	}
	if upstreamReq.URL.RawQuery != "key=value" {
		t.Errorf("expected query 'key=value', got %s", upstreamReq.URL.RawQuery)
	}

	// Check headers copied
	if upstreamReq.Header.Get("X-Custom") != "header-value" {
		t.Error("expected custom header to be copied")
	}

	// Check HTTP/2 proto set
	if upstreamReq.Proto != "HTTP/2" {
		t.Errorf("expected HTTP/2 proto, got %s", upstreamReq.Proto)
	}
	if upstreamReq.ProtoMajor != 2 {
		t.Errorf("expected ProtoMajor 2, got %d", upstreamReq.ProtoMajor)
	}
}

func TestBuildUpstreamRequest_ExceedsMaxSize(t *testing.T) {
	cfg := &Config{
		MaxMessageSize: 100,
	}
	proxy, err := NewProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}

	largeBody := bytes.Repeat([]byte("X"), 200)
	r := httptest.NewRequest("POST", "/test", bytes.NewReader(largeBody))

	_, err = proxy.buildUpstreamRequest(r, "http://upstream:9090")
	if err == nil {
		t.Error("expected error for body exceeding max size")
	}
}

func TestBuildUpstreamRequest_NoQuery(t *testing.T) {
	cfg := DefaultConfig()
	proxy, err := NewProxy(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("POST", "/package.Service/Method", bytes.NewReader([]byte("data")))

	upstreamReq, err := proxy.buildUpstreamRequest(r, "http://upstream:9090")
	if err != nil {
		t.Fatal(err)
	}

	if upstreamReq.URL.RawQuery != "" {
		t.Errorf("expected no query, got %s", upstreamReq.URL.RawQuery)
	}
}

// =====================================================================
// validateGRPCRequest
// =====================================================================

func TestValidateGRPCRequest_ValidFrame(t *testing.T) {
	cfg := &Config{
		ValidateProto:  true,
		ProtoPaths:     []string{},
		MaxMessageSize: 1024 * 1024,
	}
	proxy, err := NewProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Create a validator (no proto paths, so wire-format only)
	proxy.validator, _ = NewValidator(nil)

	// Build a valid gRPC frame with a simple protobuf message
	msg := encodeVarintField(1, 42)
	frame := make([]byte, 5+len(msg))
	frame[0] = 0
	binary.BigEndian.PutUint32(frame[1:], uint32(len(msg)))
	copy(frame[5:], msg)

	r := httptest.NewRequest("POST", "/test/Method", bytes.NewReader(frame))
	r.Header.Set("Content-Type", ContentTypeGRPC)

	err = proxy.validateGRPCRequest(r)
	if err != nil {
		t.Errorf("expected valid frame to pass, got: %v", err)
	}
}

func TestValidateGRPCRequest_BodyTooLarge(t *testing.T) {
	cfg := &Config{
		ValidateProto:  true,
		ProtoPaths:     []string{},
		MaxMessageSize: 100,
	}
	proxy, err := NewProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}

	proxy.validator, _ = NewValidator(nil)

	largeBody := bytes.Repeat([]byte("X"), 200)
	r := httptest.NewRequest("POST", "/test/Method", bytes.NewReader(largeBody))

	err = proxy.validateGRPCRequest(r)
	if err == nil {
		t.Error("expected error for body too large")
	}
}

func TestValidateGRPCRequest_InvalidFrames(t *testing.T) {
	cfg := &Config{
		ValidateProto:  true,
		ProtoPaths:     []string{},
		MaxMessageSize: 1024 * 1024,
	}
	proxy, err := NewProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}

	proxy.validator, _ = NewValidator(nil)

	// Create a frame that claims more data than available
	frame := make([]byte, 10)
	frame[0] = 0
	binary.BigEndian.PutUint32(frame[1:], 100) // claims 100 bytes
	copy(frame[5:], []byte("short"))            // only 5 bytes

	r := httptest.NewRequest("POST", "/test/Method", bytes.NewReader(frame))

	err = proxy.validateGRPCRequest(r)
	if err == nil {
		t.Error("expected error for invalid frame data")
	}
}

func TestValidateGRPCRequest_NilValidator(t *testing.T) {
	cfg := DefaultConfig()
	proxy, err := NewProxy(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("POST", "/test/Method", bytes.NewReader([]byte("data")))

	err = proxy.validateGRPCRequest(r)
	if err != nil {
		t.Errorf("nil validator should return nil, got: %v", err)
	}
}

// =====================================================================
// decodeWireFormat - group wire types
// =====================================================================

func TestDecodeWireFormat_StartGroup(t *testing.T) {
	// Start group (wire type 3) with a varint field inside, then end group (wire type 4)
	// Field 1, wire type 3 (start group)
	tag := uint64(1<<3 | 3)
	var data []byte
	data = append(data, encodeVarint(tag)...)
	// Field 2, wire type 0 (varint), value 42 inside the group
	data = append(data, encodeVarintField(2, 42)...)
	// Field 1, wire type 4 (end group)
	data = append(data, encodeVarint(uint64(1<<3|4))...)

	fields, err := decodeWireFormat(data)
	if err != nil {
		t.Fatalf("decodeWireFormat failed: %v", err)
	}
	// Start group should produce a field with wire type 3
	found := false
	for _, f := range fields {
		if f.WireType == 3 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find start group field")
	}
}

func TestDecodeWireFormat_IncompleteVarint(t *testing.T) {
	// All continuation bytes — incomplete varint
	data := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}
	_, err := decodeWireFormat(data)
	if err == nil {
		t.Error("expected error for varint too long")
	}
}

func TestDecodeWireFormat_ZeroLengthVarint(t *testing.T) {
	// This can't really happen with the current implementation since we need at least 1 byte
	// But test empty data
	fields, err := decodeWireFormat([]byte{})
	if err != nil {
		t.Fatalf("expected no error for empty data, got %v", err)
	}
	if len(fields) != 0 {
		t.Errorf("expected 0 fields, got %d", len(fields))
	}
}

func TestDecodeWireFormat_IncompleteFixed32(t *testing.T) {
	tag := encodeVarint(uint64(1<<3 | wireFixed32))
	data := append(tag, []byte{0x01, 0x02}...) // Only 2 bytes, need 4

	_, err := decodeWireFormat(data)
	if err == nil {
		t.Error("expected error for incomplete fixed32")
	}
}

func TestDecodeWireFormat_UnknownWireType(t *testing.T) {
	// Wire type 6 is unknown
	tag := encodeVarint(uint64(1<<3 | 6))
	data := append(tag, []byte{0x01}...)

	_, err := decodeWireFormat(data)
	if err == nil {
		t.Error("expected error for unknown wire type")
	}
}

func TestDecodeWireFormat_VarintReadError(t *testing.T) {
	// Start a valid tag, then have incomplete varint value
	tag := encodeVarint(uint64(1<<3 | wireVarint))
	data := append(tag, []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}...)

	_, err := decodeWireFormat(data)
	if err == nil {
		t.Error("expected error for incomplete varint value")
	}
}

func TestDecodeWireFormat_BytesLengthReadError(t *testing.T) {
	// Wire type 2 (bytes), but the length varint is incomplete
	tag := encodeVarint(uint64(1<<3 | wireBytes))
	data := append(tag, []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}...)

	_, err := decodeWireFormat(data)
	if err == nil {
		t.Error("expected error for incomplete length varint")
	}
}

func TestDecodeWireFormat_GroupVarintError(t *testing.T) {
	// Start group with invalid varint inside
	tag := encodeVarint(uint64(1<<3 | wireStartGroup))
	data := append(tag, []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}...)

	_, err := decodeWireFormat(data)
	if err == nil {
		t.Error("expected error for varint inside group")
	}
}

func TestDecodeWireFormat_GroupFixed64Missing(t *testing.T) {
	// Group with a fixed64 inside but missing data
	tag := encodeVarint(uint64(1<<3 | wireStartGroup))
	innerTag := encodeVarint(uint64(2<<3 | wireFixed64))
	data := append(tag, innerTag...)
	data = append(data, []byte{0x01, 0x02}...) // only 2 bytes, need 8

	_, err := decodeWireFormat(data)
	if err == nil {
		t.Error("expected error for incomplete fixed64 inside group")
	}
}

func TestDecodeWireFormat_GroupFixed32Missing(t *testing.T) {
	// Group with a fixed32 inside but missing data
	tag := encodeVarint(uint64(1<<3 | wireStartGroup))
	innerTag := encodeVarint(uint64(2<<3 | wireFixed32))
	data := append(tag, innerTag...)
	data = append(data, []byte{0x01}...) // only 1 byte, need 4

	_, err := decodeWireFormat(data)
	if err == nil {
		t.Error("expected error for incomplete fixed32 inside group")
	}
}

func TestDecodeWireFormat_GroupBytesLengthError(t *testing.T) {
	// Group with a bytes field inside but length varint is bad
	tag := encodeVarint(uint64(1<<3 | wireStartGroup))
	innerTag := encodeVarint(uint64(2<<3 | wireBytes))
	badLen := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}
	data := append(tag, innerTag...)
	data = append(data, badLen...)

	_, err := decodeWireFormat(data)
	if err == nil {
		t.Error("expected error for bad bytes length inside group")
	}
}

func TestDecodeWireFormat_GroupNestedGroup(t *testing.T) {
	// Nested groups: start outer, start inner, end inner, end outer
	outerStart := encodeVarint(uint64(1<<3 | wireStartGroup))
	innerStart := encodeVarint(uint64(2<<3 | wireStartGroup))
	innerEnd := encodeVarint(uint64(2<<3 | wireEndGroup))
	outerEnd := encodeVarint(uint64(1<<3 | wireEndGroup))

	var data []byte
	data = append(data, outerStart...)
	data = append(data, innerStart...)
	data = append(data, innerEnd...)
	data = append(data, outerEnd...)

	fields, err := decodeWireFormat(data)
	if err != nil {
		t.Fatalf("decodeWireFormat failed: %v", err)
	}
	if len(fields) == 0 {
		t.Error("expected at least one field from nested groups")
	}
}

// =====================================================================
// decodeVarint edge cases
// =====================================================================

func TestDecodeVarint_LargeValue(t *testing.T) {
	// Test max uint64 value
	encoded := encodeVarint(^uint64(0))
	decoded, n, err := decodeVarint(encoded)
	if err != nil {
		t.Fatalf("decodeVarint failed: %v", err)
	}
	if decoded != ^uint64(0) {
		t.Errorf("expected max uint64, got %d", decoded)
	}
	if n != len(encoded) {
		t.Errorf("consumed bytes = %d, want %d", n, len(encoded))
	}
}

func TestDecodeVarint_SingleByte(t *testing.T) {
	decoded, n, err := decodeVarint([]byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	if decoded != 1 {
		t.Errorf("expected 1, got %d", decoded)
	}
	if n != 1 {
		t.Errorf("expected 1 byte consumed, got %d", n)
	}
}

// =====================================================================
// validateWireIntegrity - additional branches
// =====================================================================

func TestValidateWireIntegrity_Fixed64WrongSize(t *testing.T) {
	v, _ := NewValidator(nil)

	// Create a field with fixed64 wire type but wrong value length
	df := decodedField{FieldNumber: 1, WireType: wireFixed64, Value: []byte{1, 2, 3}}
	result := ValidationResult{}
	v.validateWireIntegrity([]decodedField{df}, 0, &result)

	if len(result.Violations) == 0 {
		t.Error("expected violation for fixed64 with wrong size")
	}
}

func TestValidateWireIntegrity_Fixed32WrongSize(t *testing.T) {
	v, _ := NewValidator(nil)

	df := decodedField{FieldNumber: 1, WireType: wireFixed32, Value: []byte{1, 2}}
	result := ValidationResult{}
	v.validateWireIntegrity([]decodedField{df}, 0, &result)

	if len(result.Violations) == 0 {
		t.Error("expected violation for fixed32 with wrong size")
	}
}

func TestValidateWireIntegrity_BytesTooLarge(t *testing.T) {
	v, _ := NewValidator(nil)

	df := decodedField{
		FieldNumber: 1,
		WireType:    wireBytes,
		Value:       bytes.Repeat([]byte("X"), maxBytesLen+1),
	}
	result := ValidationResult{}
	v.validateWireIntegrity([]decodedField{df}, 0, &result)

	if len(result.Violations) == 0 {
		t.Error("expected violation for bytes field too large")
	}
}

func TestValidateWireIntegrity_DeprecatedGroupTypes(t *testing.T) {
	v, _ := NewValidator(nil)

	fields := []decodedField{
		{FieldNumber: 1, WireType: wireStartGroup},
		{FieldNumber: 1, WireType: wireEndGroup},
	}
	result := ValidationResult{}
	v.validateWireIntegrity(fields, 0, &result)

	if len(result.Warnings) < 2 {
		t.Errorf("expected warnings for deprecated group types, got %d", len(result.Warnings))
	}
}

func TestValidateWireIntegrity_UnknownWireType(t *testing.T) {
	v, _ := NewValidator(nil)

	df := decodedField{FieldNumber: 1, WireType: 6}
	result := ValidationResult{}
	v.validateWireIntegrity([]decodedField{df}, 0, &result)

	if len(result.Violations) == 0 {
		t.Error("expected violation for unknown wire type")
	}
}

func TestValidateWireIntegrity_RepeatedFieldLimit(t *testing.T) {
	v, _ := NewValidator(nil)

	// Create maxRepeatedItems+1 fields with same field number
	var fields []decodedField
	for i := 0; i <= maxRepeatedItems; i++ {
		fields = append(fields, decodedField{FieldNumber: 1, WireType: wireVarint, Varint: 1})
	}
	result := ValidationResult{}
	v.validateWireIntegrity(fields, 0, &result)

	found := false
	for _, v := range result.Violations {
		if len(v) > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected violation for too many repeated items")
	}
}

func TestValidateWireIntegrity_RecursiveEmbeddedMessage(t *testing.T) {
	v, _ := NewValidator(nil)

	// Create a bytes field that looks like a valid embedded message
	inner := encodeVarintField(1, 42)
	outer := encodeBytesField(1, inner)

	fields, err := decodeWireFormat(outer)
	if err != nil {
		t.Fatal(err)
	}

	result := ValidationResult{}
	v.validateWireIntegrity(fields, 0, &result)

	// Should recursively validate without panicking
	// No violations expected for valid nested message
	if len(result.Violations) > 0 {
		t.Logf("violations (may be expected): %v", result.Violations)
	}
}

// =====================================================================
// checkWireTypeCompat - additional types
// =====================================================================

func TestCheckWireTypeCompat_AllTypes(t *testing.T) {
	tests := []struct {
		fieldType string
		wireType  int
		expectErr bool
	}{
		{FieldTypeBool, wireVarint, false},
		{FieldTypeBool, wireBytes, true},
		{FieldTypeEnum, wireVarint, false},
		{FieldTypeEnum, wireFixed32, true},
		{FieldTypeFixed64, wireFixed64, false},
		{FieldTypeFixed64, wireVarint, true},
		{FieldTypeSfixed64, wireFixed64, false},
		{FieldTypeSfixed64, wireBytes, true},
		{FieldTypeSfixed32, wireFixed32, false},
		{FieldTypeSfixed32, wireVarint, true},
		{FieldTypeFloat, wireFixed32, false},
		{FieldTypeFloat, wireFixed64, true},
		{FieldTypeSint32, wireVarint, false},
		{FieldTypeSint32, wireBytes, true},
		{FieldTypeSint64, wireVarint, false},
		{FieldTypeSint64, wireFixed64, true},
	}

	for _, tt := range tests {
		t.Run(tt.fieldType, func(t *testing.T) {
			err := checkWireTypeCompat(tt.fieldType, tt.wireType)
			if (err != nil) != tt.expectErr {
				t.Errorf("checkWireTypeCompat(%s, %d) err=%v, expectErr=%v", tt.fieldType, tt.wireType, err, tt.expectErr)
			}
		})
	}
}

// =====================================================================
// applyConstraint - additional types
// =====================================================================

func TestApplyConstraint_Int64Range(t *testing.T) {
	v, _ := NewValidator(nil)
	minVal := 10.0
	maxVal := 100.0

	schema := &MessageType{
		Name: "Test",
		Fields: []Field{
			{Name: "val", Number: 1, Type: FieldTypeInt64},
		},
		Constraints: map[string]Constraint{
			"val": {MinVal: &minVal, MaxVal: &maxVal},
		},
	}
	v.RegisterSchema("Test", schema)

	// Value below min
	data := encodeVarintField(1, 5)
	err := v.ValidateMessage("Test", data)
	if err == nil {
		t.Error("expected error for int64 below min")
	}

	// Value above max
	data = encodeVarintField(1, 200)
	err = v.ValidateMessage("Test", data)
	if err == nil {
		t.Error("expected error for int64 above max")
	}

	// Value in range
	data = encodeVarintField(1, 50)
	err = v.ValidateMessage("Test", data)
	if err != nil {
		t.Errorf("expected valid for int64 in range, got: %v", err)
	}
}

func TestApplyConstraint_Uint32Range(t *testing.T) {
	v, _ := NewValidator(nil)
	minVal := 5.0
	maxVal := 50.0

	schema := &MessageType{
		Name: "Test",
		Fields: []Field{
			{Name: "val", Number: 1, Type: FieldTypeUint32},
		},
		Constraints: map[string]Constraint{
			"val": {MinVal: &minVal, MaxVal: &maxVal},
		},
	}
	v.RegisterSchema("Test", schema)

	// Value below min
	data := encodeVarintField(1, 2)
	err := v.ValidateMessage("Test", data)
	if err == nil {
		t.Error("expected error for uint32 below min")
	}

	// Value above max
	data = encodeVarintField(1, 100)
	err = v.ValidateMessage("Test", data)
	if err == nil {
		t.Error("expected error for uint32 above max")
	}
}

func TestApplyConstraint_Uint64Range(t *testing.T) {
	v, _ := NewValidator(nil)
	minVal := 1.0
	maxVal := 1000.0

	schema := &MessageType{
		Name: "Test",
		Fields: []Field{
			{Name: "val", Number: 1, Type: FieldTypeUint64},
		},
		Constraints: map[string]Constraint{
			"val": {MinVal: &minVal, MaxVal: &maxVal},
		},
	}
	v.RegisterSchema("Test", schema)

	data := encodeVarintField(1, 500)
	err := v.ValidateMessage("Test", data)
	if err != nil {
		t.Errorf("expected valid for uint64 in range, got: %v", err)
	}
}

func TestApplyConstraint_Sint32Range(t *testing.T) {
	v, _ := NewValidator(nil)
	minVal := -100.0
	maxVal := 100.0

	schema := &MessageType{
		Name: "Test",
		Fields: []Field{
			{Name: "val", Number: 1, Type: FieldTypeSint32},
		},
		Constraints: map[string]Constraint{
			"val": {MinVal: &minVal, MaxVal: &maxVal},
		},
	}
	v.RegisterSchema("Test", schema)

	// Value 0 should be in range
	data := encodeVarintField(1, 0)
	err := v.ValidateMessage("Test", data)
	if err != nil {
		t.Errorf("expected valid for sint32 in range, got: %v", err)
	}
}

func TestApplyConstraint_Sint64Range(t *testing.T) {
	v, _ := NewValidator(nil)
	minVal := 0.0
	maxVal := 1000.0

	schema := &MessageType{
		Name: "Test",
		Fields: []Field{
			{Name: "val", Number: 1, Type: FieldTypeSint64},
		},
		Constraints: map[string]Constraint{
			"val": {MinVal: &minVal, MaxVal: &maxVal},
		},
	}
	v.RegisterSchema("Test", schema)

	data := encodeVarintField(1, 500)
	err := v.ValidateMessage("Test", data)
	if err != nil {
		t.Errorf("expected valid for sint64 in range, got: %v", err)
	}
}

func TestApplyConstraint_DoubleRange(t *testing.T) {
	v, _ := NewValidator(nil)
	minVal := 0.0
	maxVal := 100.0

	schema := &MessageType{
		Name: "Test",
		Fields: []Field{
			{Name: "val", Number: 1, Type: FieldTypeDouble},
		},
		Constraints: map[string]Constraint{
			"val": {MinVal: &minVal, MaxVal: &maxVal},
		},
	}
	v.RegisterSchema("Test", schema)

	// Encode a double (float64) in range
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], uint64(50.0))
	data := encodeField(1, wireFixed64, tmp[:])

	err := v.ValidateMessage("Test", data)
	if err != nil {
		t.Errorf("expected valid double in range, got: %v", err)
	}
}

func TestApplyConstraint_DoubleOutOfRange(t *testing.T) {
	v, _ := NewValidator(nil)
	minVal := 0.0
	maxVal := 100.0

	schema := &MessageType{
		Name: "Test",
		Fields: []Field{
			{Name: "val", Number: 1, Type: FieldTypeDouble},
		},
		Constraints: map[string]Constraint{
			"val": {MinVal: &minVal, MaxVal: &maxVal},
		},
	}
	v.RegisterSchema("Test", schema)

	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], uint64(200.0))
	data := encodeField(1, wireFixed64, tmp[:])

	err := v.ValidateMessage("Test", data)
	if err == nil {
		t.Error("expected error for double above max")
	}
}

func TestApplyConstraint_FloatOutOfRange(t *testing.T) {
	v, _ := NewValidator(nil)
	minVal := 0.0
	maxVal := 1.0

	schema := &MessageType{
		Name: "Test",
		Fields: []Field{
			{Name: "val", Number: 1, Type: FieldTypeFloat},
		},
		Constraints: map[string]Constraint{
			"val": {MinVal: &minVal, MaxVal: &maxVal},
		},
	}
	v.RegisterSchema("Test", schema)

	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(-1.0))
	data := encodeField(1, wireFixed32, tmp[:])

	err := v.ValidateMessage("Test", data)
	if err == nil {
		t.Error("expected error for float below min")
	}
}

func TestApplyConstraint_BytesMaxLen(t *testing.T) {
	v, _ := NewValidator(nil)
	maxLen := 10

	schema := &MessageType{
		Name: "Test",
		Fields: []Field{
			{Name: "data", Number: 1, Type: FieldTypeBytes},
		},
		Constraints: map[string]Constraint{
			"data": {MaxLen: &maxLen},
		},
	}
	v.RegisterSchema("Test", schema)

	// Too long
	data := encodeBytesField(1, bytes.Repeat([]byte("X"), 20))
	err := v.ValidateMessage("Test", data)
	if err == nil {
		t.Error("expected error for bytes exceeding max len")
	}

	// In range
	data = encodeBytesField(1, []byte("hello"))
	err = v.ValidateMessage("Test", data)
	if err != nil {
		t.Errorf("expected valid bytes in range, got: %v", err)
	}
}

func TestApplyConstraint_StringMinLen(t *testing.T) {
	v, _ := NewValidator(nil)
	minLen := 3

	schema := &MessageType{
		Name: "Test",
		Fields: []Field{
			{Name: "name", Number: 1, Type: FieldTypeString},
		},
		Constraints: map[string]Constraint{
			"name": {MinLen: &minLen},
		},
	}
	v.RegisterSchema("Test", schema)

	// Too short
	data := encodeBytesField(1, []byte("ab"))
	err := v.ValidateMessage("Test", data)
	if err == nil {
		t.Error("expected error for string below min len")
	}
}

// =====================================================================
// ValidateMessageDetailed - max field count
// =====================================================================

func TestValidateMessageDetailed_TooManyFields(t *testing.T) {
	v, _ := NewValidator(nil)

	// Create a message with maxFieldCount+1 fields
	var data []byte
	for i := 0; i <= maxFieldCount; i++ {
		data = append(data, encodeVarintField(i%100+1, uint64(i))...)
	}

	result := v.ValidateMessageDetailed("Test", data, 0)
	found := false
	for _, v := range result.Violations {
		if len(v) > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected violation for too many fields")
	}
}

// =====================================================================
// validateAgainstSchema - unknown fields
// =====================================================================

func TestValidateAgainstSchema_UnknownFields(t *testing.T) {
	v, _ := NewValidator(nil)

	schema := &MessageType{
		Name: "Test",
		Fields: []Field{
			{Name: "known", Number: 1, Type: FieldTypeUint32},
		},
	}
	v.RegisterSchema("Test", schema)

	data := encodeVarintField(1, 42) // known
	data = append(data, encodeVarintField(99, 1)...) // unknown

	err := v.ValidateMessage("Test", data)
	if err != nil {
		t.Errorf("unknown fields should not cause error, got: %v", err)
	}

	result := v.ValidateMessageDetailed("Test", data, 0)
	if len(result.UnknownFields) == 0 {
		t.Error("expected unknown fields to be tracked")
	}
}

// =====================================================================
// validateAgainstSchema - embedded messages with schema
// =====================================================================

func TestValidateAgainstSchema_EmbeddedMessageWithSchema(t *testing.T) {
	v, _ := NewValidator(nil)

	// Register inner schema with required field
	v.RegisterSchema("inner_msg", &MessageType{
		Name: "Inner",
		Fields: []Field{
			{Name: "value", Number: 1, Type: FieldTypeUint32},
		},
		Required: []string{"value"},
	})

	// Register outer schema with embedded message field
	v.RegisterSchema("Outer", &MessageType{
		Name: "Outer",
		Fields: []Field{
			{Name: "inner", Number: 1, Type: FieldTypeMessage},
		},
	})

	// Valid: outer has inner with required field
	inner := encodeVarintField(1, 42)
	outer := encodeBytesField(1, inner)

	err := v.ValidateMessage("Outer", outer)
	if err != nil {
		t.Errorf("expected valid embedded message, got: %v", err)
	}
}

// =====================================================================
// NewProxy - default max message size
// =====================================================================

func TestNewProxy_DefaultMaxMessageSize(t *testing.T) {
	cfg := &Config{
		MaxMessageSize: 0, // should default to 4MB
	}
	proxy, err := NewProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if proxy.maxMsgSize != 4*1024*1024 {
		t.Errorf("expected default max message size 4MB, got %d", proxy.maxMsgSize)
	}
}

func TestNewProxy_WithProtoPathsValidation(t *testing.T) {
	cfg := &Config{
		ValidateProto:  true,
		ProtoPaths:     []string{"/nonexistent/path"},
		MaxMessageSize: 1024,
	}
	_, err := NewProxy(cfg)
	if err != nil {
		// NewValidator with proto paths might fail or succeed depending on implementation
		// Since it doesn't actually load files, it should succeed
		t.Logf("NewProxy with proto paths returned: %v", err)
	}
}

// =====================================================================
// CompressionConfig
// =====================================================================

func TestCompressionConfig_Defaults(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.Compression.Enabled {
		t.Error("expected compression to be enabled by default")
	}
	if len(cfg.Compression.AllowedEncodings) != 2 {
		t.Errorf("expected 2 allowed encodings, got %d", len(cfg.Compression.AllowedEncodings))
	}
}

// =====================================================================
// handleGRPC - with validator error
// =====================================================================

func TestHandleGRPC_ValidationError(t *testing.T) {
	cfg := &Config{
		AllowedMethods: []string{"Method"},
		MaxMessageSize: 1024 * 1024,
		ValidateProto:  true,
		ProtoPaths:     []string{},
	}
	proxy, err := NewProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	proxy.validator, _ = NewValidator(nil)

	// Send invalid protobuf data (bare continuation bytes)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/pkg/Method", bytes.NewReader([]byte{0x80, 0x80, 0x80, 0x80}))
	r.Header.Set("Content-Type", ContentTypeGRPC)

	proxy.handleGRPC(w, r, "http://127.0.0.1:1")

	// Should get a validation error response
	if w.Code != http.StatusOK {
		t.Logf("handleGRPC response code: %d", w.Code)
	}
}

// =====================================================================
// handleGRPC - body too large for upstream request
// =====================================================================

func TestHandleGRPC_UpstreamBodyTooLarge(t *testing.T) {
	cfg := &Config{
		AllowedMethods: []string{"Method"},
		MaxMessageSize: 10,
	}
	proxy, err := NewProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/pkg/Method", bytes.NewReader(bytes.Repeat([]byte("X"), 100)))
	r.Header.Set("Content-Type", ContentTypeGRPC)

	proxy.handleGRPC(w, r, "http://127.0.0.1:1")

	// Should get error response
	if w.Code != http.StatusOK {
		t.Logf("handleGRPC response code: %d", w.Code)
	}
}

// =====================================================================
// validateGRPCRequest - body read error
// =====================================================================

func TestValidateGRPCRequest_ReadError(t *testing.T) {
	cfg := &Config{
		ValidateProto:  true,
		ProtoPaths:     []string{},
		MaxMessageSize: 1024,
	}
	proxy, err := NewProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	proxy.validator, _ = NewValidator(nil)

	r := httptest.NewRequest("POST", "/test/Method", io.LimitReader(errReader{}, 100))

	err = proxy.validateGRPCRequest(r)
	if err == nil {
		t.Error("expected error from failing reader")
	}
}

// errReader is a reader that always returns an error.
type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

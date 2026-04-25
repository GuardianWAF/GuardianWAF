package websocket

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// ---------------------------------------------------------------------------
// Handshake validation — comprehensive
// ---------------------------------------------------------------------------

func TestValidateHandshake_MissingWebSocketKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/ws"},
		Header: http.Header{
			"Upgrade":    []string{"websocket"},
			"Connection": []string{"Upgrade"},
		},
	}

	if err := security.ValidateHandshake(req); err == nil {
		t.Error("expected error for missing Sec-WebSocket-Key")
	}
}

func TestValidateHandshake_BlockedExtension(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.BlockedExtensions = []string{".exe", ".dll"}
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/ws/payload.exe"},
		Header: http.Header{
			"Upgrade":            []string{"websocket"},
			"Connection":         []string{"Upgrade"},
			"Sec-Websocket-Key":  []string{"dGhlIHNhbXBsZSBub25jZQ=="},
		},
	}

	if err := security.ValidateHandshake(req); err == nil || !strings.Contains(err.Error(), "blocked extension") {
		t.Errorf("expected blocked extension error, got: %v", err)
	}
}

func TestValidateHandshake_NotUpgradeRequest(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/api"},
		Header: http.Header{},
	}

	if err := security.ValidateHandshake(req); err == nil {
		t.Error("expected error for non-upgrade request")
	}
}

func TestValidateHandshake_DisabledSecurity(t *testing.T) {
	cfg := &Config{Enabled: false}
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/ws"},
		Header: http.Header{
			"Upgrade":           []string{"websocket"},
			"Connection":        []string{"Upgrade"},
			"Sec-Websocket-Key": []string{"dGhlIHNhbXBsZSBub25jZQ=="},
		},
	}

	if err := security.ValidateHandshake(req); err != nil {
		t.Errorf("disabled security should pass everything: %v", err)
	}
}

func TestValidateHandshake_MaxConcurrentPerIP(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.MaxConcurrentPerIP = 2
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	// Register 2 connections from the same IP
	security.RegisterConnection("c1", "10.0.0.1", "", "/ws")
	security.RegisterConnection("c2", "10.0.0.1", "", "/ws")

	req := &http.Request{
		Method:     "GET",
		URL:        &url.URL{Path: "/ws"},
		RemoteAddr: "10.0.0.1:1234",
		Header: http.Header{
			"Upgrade":           []string{"websocket"},
			"Connection":        []string{"Upgrade"},
			"Sec-Websocket-Key": []string{"dGhlIHNhbXBsZSBub25jZQ=="},
		},
	}

	if err := security.ValidateHandshake(req); err == nil || !strings.Contains(err.Error(), "max concurrent") {
		t.Errorf("expected max concurrent error, got: %v", err)
	}
}

func TestValidateHandshake_ValidSameOrigin(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	// Empty AllowedOrigins => same-origin policy
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/ws"},
		Host:   "example.com",
		Header: http.Header{
			"Upgrade":           []string{"websocket"},
			"Connection":        []string{"Upgrade"},
			"Sec-Websocket-Key": []string{"dGhlIHNhbXBsZSBub25jZQ=="},
			"Origin":            []string{"https://example.com"},
		},
	}

	if err := security.ValidateHandshake(req); err != nil {
		t.Errorf("same-origin request should pass: %v", err)
	}
}

func TestValidateHandshake_CrossOriginRejected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	// Empty AllowedOrigins => same-origin policy, cross-origin rejected
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/ws"},
		Host:   "example.com",
		Header: http.Header{
			"Upgrade":           []string{"websocket"},
			"Connection":        []string{"Upgrade"},
			"Sec-Websocket-Key": []string{"dGhlIHNhbXBsZSBub25jZQ=="},
			"Origin":            []string{"https://evil.com"},
		},
	}

	if err := security.ValidateHandshake(req); err == nil {
		t.Error("cross-origin request should be rejected")
	}
}

// ---------------------------------------------------------------------------
// Message size limits
// ---------------------------------------------------------------------------

func TestValidateFrame_MaxFrameSizeExceeded(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.MaxFrameSize = 64
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	conn := &Connection{
		ID:          "test",
		RateLimiter: NewRateLimiter(100, 100),
	}

	frame := &Frame{Opcode: OpText, Payload: make([]byte, 65)}
	if err := security.ValidateFrame(conn, frame); err == nil {
		t.Error("expected frame-too-large error")
	}
}

func TestValidateFrame_MaxMessageSizeExceeded(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.MaxMessageSize = 128
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	conn := &Connection{
		ID:          "test",
		RateLimiter: NewRateLimiter(100, 100),
	}

	frame := &Frame{Opcode: OpText, Payload: make([]byte, 200)}
	if err := security.ValidateFrame(conn, frame); err == nil {
		t.Error("expected message-too-large error")
	}
}

func TestValidateFrame_ControlFramesSkipMessageSizeCheck(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.MaxMessageSize = 10
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	conn := &Connection{
		ID:          "test",
		RateLimiter: NewRateLimiter(100, 100),
	}

	// Control frames (ping/pong/close) should not be checked against MaxMessageSize
	frame := &Frame{Opcode: OpPing, Payload: make([]byte, 50)}
	if err := security.ValidateFrame(conn, frame); err != nil {
		t.Errorf("control frame should skip message size check: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Rate limiting per connection
// ---------------------------------------------------------------------------

func TestValidateFrame_RateLimitExceeded(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	// Small burst = 2, then deny
	conn := &Connection{
		ID:          "test",
		RateLimiter: NewRateLimiter(1, 2),
	}

	frame := &Frame{Opcode: OpText, Payload: []byte("hi")}

	// First two should succeed
	for i := 0; i < 2; i++ {
		if err := security.ValidateFrame(conn, frame); err != nil {
			t.Fatalf("frame %d should pass: %v", i+1, err)
		}
	}

	// Third should be rate limited
	if err := security.ValidateFrame(conn, frame); err == nil {
		t.Error("expected rate limit error")
	}
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	rl := NewRateLimiter(10000, 5000)
	var wg sync.WaitGroup
	allowed := int64(0)
	denied := int64(0)
	var mu sync.Mutex

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rl.Allow() {
				mu.Lock()
				allowed++
				mu.Unlock()
			} else {
				mu.Lock()
				denied++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if allowed == 0 {
		t.Error("expected some allowed requests")
	}
	if allowed+denied != 100 {
		t.Errorf("expected 100 total decisions, got %d", allowed+denied)
	}
}

// ---------------------------------------------------------------------------
// Frame validation (ParseFrame edge cases)
// ---------------------------------------------------------------------------

func TestParseFrame_ExtendedPayload126(t *testing.T) {
	// Build a frame with 126-byte payload using 2-byte extended length
	payload := make([]byte, 200)
	for i := range payload {
		payload[i] = byte(i)
	}

	var buf bytes.Buffer
	// FIN=1, opcode=text
	buf.WriteByte(0x81)
	// Length=126 means extended 2-byte length follows
	buf.WriteByte(126)
	binary.Write(&buf, binary.BigEndian, uint16(len(payload)))
	buf.Write(payload)

	frame, err := ParseFrame(&buf)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if frame.PayloadLen != uint64(len(payload)) {
		t.Errorf("PayloadLen = %d, want %d", frame.PayloadLen, len(payload))
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Error("payload mismatch")
	}
}

func TestParseFrame_ExtendedPayload127(t *testing.T) {
	payload := make([]byte, 300)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	var buf bytes.Buffer
	buf.WriteByte(0x82) // binary frame
	buf.WriteByte(127)  // 8-byte extended length
	binary.Write(&buf, binary.BigEndian, uint64(len(payload)))
	buf.Write(payload)

	frame, err := ParseFrame(&buf)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if frame.PayloadLen != uint64(len(payload)) {
		t.Errorf("PayloadLen = %d, want %d", frame.PayloadLen, len(payload))
	}
}

func TestParseFrame_TooLarge(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(0x81) // text frame
	buf.WriteByte(127)  // 8-byte extended length
	binary.Write(&buf, binary.BigEndian, uint64(3*1024*1024)) // 3MB > 2MB limit

	_, err := ParseFrame(&buf)
	if err == nil {
		t.Error("expected error for oversized frame")
	}
}

func TestParseFrame_IncompleteHeader(t *testing.T) {
	// Only 1 byte, missing second byte
	_, err := ParseFrame(bytes.NewReader([]byte{0x81}))
	if err == nil {
		t.Error("expected error for incomplete frame header")
	}
}

func TestParseFrame_EmptyInput(t *testing.T) {
	_, err := ParseFrame(bytes.NewReader([]byte{}))
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestParseFrame_MaskedButMissingMaskKey(t *testing.T) {
	// Masked frame with payload but no mask key bytes
	_, err := ParseFrame(bytes.NewReader([]byte{0x81, 0x80}))
	if err == nil {
		t.Error("expected error for missing mask key")
	}
}

func TestWriteFrame_ExtendedPayload126(t *testing.T) {
	payload := make([]byte, 200)
	frame := &Frame{
		Fin:     true,
		Opcode:  OpText,
		Payload: payload,
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, frame); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	parsed, err := ParseFrame(&buf)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if parsed.PayloadLen != uint64(len(payload)) {
		t.Errorf("PayloadLen = %d, want %d", parsed.PayloadLen, len(payload))
	}
}

func TestWriteFrame_LargePayload(t *testing.T) {
	payload := make([]byte, 70000)
	frame := &Frame{
		Fin:     true,
		Opcode:  OpBinary,
		Payload: payload,
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, frame); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	parsed, err := ParseFrame(&buf)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if parsed.PayloadLen != uint64(len(payload)) {
		t.Errorf("PayloadLen = %d, want %d", parsed.PayloadLen, len(payload))
	}
}

func TestWriteFrame_Masked(t *testing.T) {
	frame := &Frame{
		Fin:     true,
		Opcode:  OpText,
		Masked:  true,
		MaskKey: [4]byte{0xAA, 0xBB, 0xCC, 0xDD},
		Payload: []byte("Hello masked world"),
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, frame); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	parsed, err := ParseFrame(&buf)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if !parsed.Masked {
		t.Error("expected masked frame")
	}
	if string(parsed.Payload) != "Hello masked world" {
		t.Errorf("payload = %q, want %q", string(parsed.Payload), "Hello masked world")
	}
}

func TestWriteFrame_WithRSVBits(t *testing.T) {
	frame := &Frame{
		Fin:     true,
		Rsv1:    true,
		Rsv2:    true,
		Rsv3:    true,
		Opcode:  OpBinary,
		Payload: []byte("rsv"),
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, frame); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	parsed, err := ParseFrame(&buf)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if !parsed.Rsv1 || !parsed.Rsv2 || !parsed.Rsv3 {
		t.Error("RSV bits should be preserved")
	}
}

func TestWriteFrame_EmptyPayload(t *testing.T) {
	frame := &Frame{
		Fin:     true,
		Opcode:  OpText,
		Payload: []byte{},
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, frame); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	parsed, err := ParseFrame(&buf)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if len(parsed.Payload) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(parsed.Payload))
	}
}

// ---------------------------------------------------------------------------
// Idle timeout / cleanup
// ---------------------------------------------------------------------------

func TestCleanupStaleConnections_ZeroTimeout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.IdleTimeout = 0
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	security.RegisterConnection("c1", "1.2.3.4", "", "/ws")
	security.CleanupStaleConnections()

	if _, ok := security.GetConnection("c1"); !ok {
		t.Error("zero timeout should not clean up connections")
	}
}

func TestCleanupStaleConnections_OnlyIdleRemoved(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.IdleTimeout = 200 * time.Millisecond
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	// Register connection and immediately touch it
	conn := security.RegisterConnection("fresh", "1.2.3.4", "", "/ws")
	// Force LastSeen into the past for a stale one
	security.RegisterConnection("stale", "5.6.7.8", "", "/ws")
	security.connMu.Lock()
	if c, ok := security.connections["stale"]; ok {
		c.mu.Lock()
		c.LastSeen = time.Now().Add(-1 * time.Hour)
		c.mu.Unlock()
	}
	security.connMu.Unlock()

	_ = conn
	security.CleanupStaleConnections()

	if _, ok := security.GetConnection("stale"); ok {
		t.Error("stale connection should be removed")
	}
	if _, ok := security.GetConnection("fresh"); !ok {
		t.Error("fresh connection should remain")
	}
}

func TestCleanupStaleConnections_MultipleIPs(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.IdleTimeout = 50 * time.Millisecond
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	security.RegisterConnection("c1", "1.1.1.1", "", "/ws")
	security.RegisterConnection("c2", "2.2.2.2", "", "/ws")
	security.RegisterConnection("c3", "1.1.1.1", "", "/ws")

	time.Sleep(80 * time.Millisecond)
	security.CleanupStaleConnections()

	if count := len(security.GetAllConnections()); count != 0 {
		t.Errorf("all idle connections should be cleaned up, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// Payload scanning
// ---------------------------------------------------------------------------

func TestScanPayload_AllThreatTypes(t *testing.T) {
	cfg := &Config{ScanPayloads: true}
	security := &Security{config: cfg}

	cases := map[string]string{
		"select * from users":      "sqli",
		"INSERT INTO users":        "sqli",
		"UPDATE users SET":         "sqli",
		"DELETE FROM users":        "sqli",
		"DROP TABLE users":         "sqli",
		"UNION SELECT":             "sqli",
		"<script>alert(1)":         "xss",
		"javascript:alert(1)":      "xss",
		"onerror=alert(1)":         "xss",
		"onload=evil()":            "xss",
		"../../../etc/passwd":      "path_traversal",
		"..\\windows\\system32":    "path_traversal",
		"/etc/passwd":              "lfi",
		"c:\\windows\\system32":    "lfi",
		"${jndi:ldap://evil}":      "log4j",
		"${template}":              "template_injection",
		"__proto__.polluted":       "prototype_pollution",
		"constructor.prototype":    "prototype_pollution",
		"normal safe text":         "",
	}

	for payload, want := range cases {
		got := security.scanPayload([]byte(payload))
		if got != want {
			t.Errorf("scanPayload(%q) = %q, want %q", payload, got, want)
		}
	}
}

func TestScanPayload_CaseInsensitive(t *testing.T) {
	cfg := &Config{ScanPayloads: true}
	security := &Security{config: cfg}

	cases := []struct {
		payload string
		threat  string
	}{
		{"SELECT * FROM users", "sqli"},
		{"SeLeCt 1", "sqli"},
		{"<SCRIPT>alert(1)</SCRIPT>", "xss"},
		{"JAVASCRIPT:evil()", "xss"},
	}

	for _, tc := range cases {
		got := security.scanPayload([]byte(tc.payload))
		if got != tc.threat {
			t.Errorf("scanPayload(%q) = %q, want %q", tc.payload, got, tc.threat)
		}
	}
}

func TestScanPayload_TabSeparatedSQL(t *testing.T) {
	cfg := &Config{ScanPayloads: true}
	security := &Security{config: cfg}

	// Tab after select keyword
	got := security.scanPayload([]byte("select\t* from users"))
	if got != "sqli" {
		t.Errorf("tab-separated select: got %q, want sqli", got)
	}
}

func TestValidateFrame_BlockEmptyMessages(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.BlockEmptyMessages = true
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	conn := &Connection{
		ID:          "test",
		RateLimiter: NewRateLimiter(100, 100),
	}

	// Empty data frame should be blocked
	frame := &Frame{Opcode: OpText, Payload: []byte{}}
	if err := security.ValidateFrame(conn, frame); err == nil {
		t.Error("expected block for empty message")
	}

	// Empty control frame should pass (control frames are always allowed)
	pingFrame := &Frame{Opcode: OpPing, Payload: []byte{}}
	if err := security.ValidateFrame(conn, pingFrame); err != nil {
		t.Errorf("control frame should be allowed even when empty: %v", err)
	}
}

func TestValidateFrame_BlockBinaryMessages(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.BlockBinaryMessages = true
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	conn := &Connection{
		ID:          "test",
		RateLimiter: NewRateLimiter(100, 100),
	}

	frame := &Frame{Opcode: OpBinary, Payload: []byte{0x01, 0x02}}
	if err := security.ValidateFrame(conn, frame); err == nil {
		t.Error("expected block for binary message")
	}

	textFrame := &Frame{Opcode: OpText, Payload: []byte("hello")}
	if err := security.ValidateFrame(conn, textFrame); err != nil {
		t.Errorf("text frame should pass: %v", err)
	}
}

func TestValidateFrame_ScanPayloadThreat(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ScanPayloads = true
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	conn := &Connection{
		ID:          "test",
		RateLimiter: NewRateLimiter(100, 100),
	}

	frame := &Frame{Opcode: OpText, Payload: []byte("<script>alert(1)</script>")}
	if err := security.ValidateFrame(conn, frame); err == nil {
		t.Error("expected threat detection error")
	}
}

func TestValidateFrame_ScanPayloadSkipsBinary(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ScanPayloads = true
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	conn := &Connection{
		ID:          "test",
		RateLimiter: NewRateLimiter(100, 100),
	}

	// Binary frame with SQL-like content — scanning only applies to text frames
	frame := &Frame{Opcode: OpBinary, Payload: []byte("SELECT * FROM users")}
	if err := security.ValidateFrame(conn, frame); err != nil {
		t.Errorf("binary frames should skip payload scanning: %v", err)
	}
}

func TestValidateFrame_DisabledSecurity(t *testing.T) {
	cfg := &Config{Enabled: false}
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	conn := &Connection{
		ID:          "test",
		RateLimiter: NewRateLimiter(100, 100),
	}

	frame := &Frame{Opcode: OpText, Payload: make([]byte, 99999)}
	if err := security.ValidateFrame(conn, frame); err != nil {
		t.Errorf("disabled security should pass everything: %v", err)
	}
}

func TestValidateFrame_UpdatesConnectionStats(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	conn := &Connection{
		ID:          "test",
		RateLimiter: NewRateLimiter(100, 100),
	}

	frame := &Frame{Opcode: OpText, Payload: []byte("hello world")}
	if err := security.ValidateFrame(conn, frame); err != nil {
		t.Fatalf("ValidateFrame: %v", err)
	}

	conn.mu.RLock()
	msgCount := conn.MsgCount
	byteCount := conn.ByteCount
	conn.mu.RUnlock()

	if msgCount != 1 {
		t.Errorf("MsgCount = %d, want 1", msgCount)
	}
	if byteCount != int64(len("hello world")) {
		t.Errorf("ByteCount = %d, want %d", byteCount, len("hello world"))
	}
}

// ---------------------------------------------------------------------------
// Process method — layer integration
// ---------------------------------------------------------------------------

func TestLayer_Process_DisabledLayer(t *testing.T) {
	cfg := &Config{Enabled: false}
	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}

	req := &http.Request{
		Method:     "GET",
		URL:        &url.URL{Path: "/ws"},
		RemoteAddr: "1.2.3.4:1234",
		Header: http.Header{
			"Upgrade":           []string{"websocket"},
			"Connection":        []string{"Upgrade"},
			"Sec-Websocket-Key": []string{"dGhlIHNhbXBsZSBub25jZQ=="},
		},
	}

	ctx := &engine.RequestContext{Request: req}
	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("disabled layer should pass, got %v", result.Action)
	}
}

func TestLayer_Process_ValidHandshake(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}
	defer layer.Stop()

	req := &http.Request{
		Method:     "GET",
		URL:        &url.URL{Path: "/ws"},
		Host:       "example.com",
		RemoteAddr: "1.2.3.4:1234",
		Header: http.Header{
			"Upgrade":           []string{"websocket"},
			"Connection":        []string{"Upgrade"},
			"Sec-Websocket-Key": []string{"dGhlIHNhbXBsZSBub25jZQ=="},
		},
	}

	ctx := &engine.RequestContext{Request: req}
	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("valid handshake should pass, got %v", result.Action)
	}
}

func TestLayer_Process_TenantOverride(t *testing.T) {
	// Test that tenant WAF config disabling WebSocket causes pass
	cfg := DefaultConfig()
	cfg.Enabled = true
	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}
	defer layer.Stop()

	req := &http.Request{
		Method:     "GET",
		URL:        &url.URL{Path: "/ws"},
		RemoteAddr: "1.2.3.4:1234",
		Header: http.Header{
			"Upgrade":           []string{"websocket"},
			"Connection":        []string{"Upgrade"},
			"Sec-Websocket-Key": []string{"dGhlIHNhbXBsZSBub25jZQ=="},
		},
	}

	// Simulate tenant override disabling WebSocket
	tenantCfg := &config.WAFConfig{}
	tenantCfg.WebSocket.Enabled = false

	ctx := &engine.RequestContext{
		Request:         req,
		TenantWAFConfig: tenantCfg,
	}

	// When tenant config explicitly disables WebSocket, the layer should pass
	// even though the global config is enabled.
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass when tenant disables WebSocket, got %v", result.Action)
	}
}

func TestLayer_Process_FindingDetails(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AllowedOrigins = []string{"https://allowed.com"}
	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}
	defer layer.Stop()

	req := &http.Request{
		Method:     "GET",
		URL:        &url.URL{Path: "/ws"},
		Host:       "allowed.com",
		RemoteAddr: "1.2.3.4:1234",
		Header: http.Header{
			"Upgrade":           []string{"websocket"},
			"Connection":        []string{"Upgrade"},
			"Sec-Websocket-Key": []string{},
		}, // Missing key
	}

	ctx := &engine.RequestContext{Request: req}
	result := layer.Process(ctx)

	if result.Action != engine.ActionBlock {
		t.Fatalf("expected block, got %v", result.Action)
	}
	if result.Score != 100 {
		t.Errorf("Score = %d, want 100", result.Score)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings")
	}

	f := result.Findings[0]
	if f.DetectorName != "websocket" {
		t.Errorf("DetectorName = %q, want websocket", f.DetectorName)
	}
	if f.Severity != engine.SeverityHigh {
		t.Errorf("Severity = %v, want SeverityHigh", f.Severity)
	}
}

// ---------------------------------------------------------------------------
// Layer lifecycle
// ---------------------------------------------------------------------------

func TestLayer_NewLayer_NilConfig(t *testing.T) {
	layer, err := NewLayer(nil)
	if err != nil {
		t.Fatalf("NewLayer(nil): %v", err)
	}
	if layer == nil {
		t.Fatal("layer should not be nil")
	}
	if layer.Name() != "websocket" {
		t.Errorf("Name = %q, want websocket", layer.Name())
	}
}

func TestLayer_Order(t *testing.T) {
	layer, _ := NewLayer(nil)
	if layer.Order() != 76 {
		t.Errorf("Order = %d, want 76", layer.Order())
	}
}

func TestLayer_Stop_NilSecurity(t *testing.T) {
	cfg := &Config{Enabled: false}
	layer, _ := NewLayer(cfg)
	// Should not panic
	layer.Stop()
}

func TestLayer_GetSecurity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}
	defer layer.Stop()

	sec := layer.GetSecurity()
	if sec == nil {
		t.Error("GetSecurity should return non-nil when enabled")
	}
}

func TestLayer_GetSecurity_Disabled(t *testing.T) {
	cfg := &Config{Enabled: false}
	layer, _ := NewLayer(cfg)

	if sec := layer.GetSecurity(); sec != nil {
		t.Error("GetSecurity should return nil when disabled")
	}
}

func TestLayer_Stop_DoubleStop(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}
	// Double stop should not panic
	layer.Stop()
	layer.Stop()
}

// ---------------------------------------------------------------------------
// Connection management
// ---------------------------------------------------------------------------

func TestConnection_StatsTracking(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	conn := security.RegisterConnection("stats-test", "10.0.0.1", "https://example.com", "/ws")
	if conn == nil {
		t.Fatal("connection should not be nil")
	}

	// Simulate messages via ValidateFrame
	frame := &Frame{Opcode: OpText, Payload: []byte("hello")}
	for i := 0; i < 5; i++ {
		if err := security.ValidateFrame(conn, frame); err != nil {
			t.Fatalf("ValidateFrame %d: %v", i, err)
		}
	}

	snap, ok := security.GetConnection("stats-test")
	if !ok {
		t.Fatal("connection should exist")
	}
	if snap.MsgCount != 5 {
		t.Errorf("MsgCount = %d, want 5", snap.MsgCount)
	}

	// GetStats should include this connection
	stats := security.GetStats()
	if stats.ActiveConnections != 1 {
		t.Errorf("ActiveConnections = %d, want 1", stats.ActiveConnections)
	}
	if stats.TotalMessages < 5 {
		t.Errorf("TotalMessages = %d, want >= 5", stats.TotalMessages)
	}
}

func TestSecurity_GetStats_NoConnections(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	stats := security.GetStats()
	if stats.ActiveConnections != 0 {
		t.Errorf("ActiveConnections = %d, want 0", stats.ActiveConnections)
	}
}

func TestSecurity_RegisterUnregister(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	security.RegisterConnection("c1", "1.1.1.1", "", "/ws")
	security.RegisterConnection("c2", "2.2.2.2", "", "/ws")

	if count := len(security.GetAllConnections()); count != 2 {
		t.Fatalf("expected 2 connections, got %d", count)
	}

	security.UnregisterConnection("c1")
	if count := len(security.GetAllConnections()); count != 1 {
		t.Errorf("expected 1 connection after unregister, got %d", count)
	}
}

func TestSecurity_UnregisterNonExistent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	// Should not panic
	security.UnregisterConnection("nonexistent")
}

// ---------------------------------------------------------------------------
// Handler (HTTP API)
// ---------------------------------------------------------------------------

func TestHandler_Stats(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	security.RegisterConnection("h1", "1.2.3.4", "", "/ws")

	handler := NewHandler(security)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/websocket/stats", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var stats Stats
	if err := json.NewDecoder(w.Body).Decode(&stats); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if stats.ActiveConnections != 1 {
		t.Errorf("ActiveConnections = %d, want 1", stats.ActiveConnections)
	}
}

func TestHandler_Stats_MethodNotAllowed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	handler := NewHandler(security)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/websocket/stats", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHandler_Connections(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	security.RegisterConnection("h1", "1.2.3.4", "https://example.com", "/ws")

	handler := NewHandler(security)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/websocket/connections", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp struct {
		Connections []struct {
			ID string `json:"id"`
		} `json:"connections"`
		Count int `json:"count"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 1 {
		t.Errorf("count = %d, want 1", resp.Count)
	}
	if len(resp.Connections) != 1 || resp.Connections[0].ID != "h1" {
		t.Errorf("unexpected connections: %+v", resp.Connections)
	}
}

func TestHandler_Connections_MethodNotAllowed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	handler := NewHandler(security)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/websocket/connections", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHandler_NotFound(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity: %v", err)
	}
	defer security.Stop()

	handler := NewHandler(security)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/websocket/unknown", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Origin validation edge cases
// ---------------------------------------------------------------------------

func TestIsAllowedOrigin_WildcardExactMatch(t *testing.T) {
	cfg := &Config{
		AllowedOrigins: []string{
			"https://example.com",
			"https://*.test.com",
		},
	}
	security := &Security{config: cfg}

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Host = "example.com"

	if !security.isAllowedOrigin("https://example.com", req) {
		t.Error("exact match should be allowed")
	}
	if !security.isAllowedOrigin("https://sub.test.com", req) {
		t.Error("wildcard subdomain should be allowed")
	}
	if !security.isAllowedOrigin("https://deep.sub.test.com", req) {
		t.Error("deep wildcard subdomain should be allowed")
	}
	if security.isAllowedOrigin("http://example.com", req) {
		t.Error("wrong scheme should be rejected")
	}
	if security.isAllowedOrigin("https://test.com", req) {
		t.Error("bare domain without subdomain should be rejected for *.test.com")
	}
}

func TestIsAllowedOrigin_InvalidURL(t *testing.T) {
	cfg := &Config{AllowedOrigins: []string{}}
	security := &Security{config: cfg}

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Host = "example.com"

	// Invalid URL should be rejected
	if security.isAllowedOrigin("://invalid", req) {
		t.Error("invalid URL should be rejected")
	}
}

// ---------------------------------------------------------------------------
// Frame helper functions
// ---------------------------------------------------------------------------

func TestCreateCloseFrame_EmptyReason(t *testing.T) {
	frame := CreateCloseFrame(1000, "")
	if frame.Opcode != OpClose {
		t.Errorf("Opcode = %d, want OpClose", frame.Opcode)
	}
	if !frame.Fin {
		t.Error("close frame should be final")
	}
	if len(frame.Payload) != 2 {
		t.Errorf("Payload length = %d, want 2 (code only)", len(frame.Payload))
	}
	code := binary.BigEndian.Uint16(frame.Payload[:2])
	if code != 1000 {
		t.Errorf("code = %d, want 1000", code)
	}
}

func TestCreateTextFrame_Empty(t *testing.T) {
	frame := CreateTextFrame("")
	if frame.Opcode != OpText {
		t.Errorf("Opcode = %d, want OpText", frame.Opcode)
	}
	if len(frame.Payload) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(frame.Payload))
	}
}

func TestIsValidUTF8_EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		valid bool
	}{
		{"empty", []byte{}, true},
		{"ascii", []byte("hello"), true},
		{"2-byte", []byte{0xc3, 0xa9}, true}, // e-acute
		{"3-byte", []byte{0xe4, 0xb8, 0xad}, true}, // Chinese character
		{"4-byte", []byte{0xf0, 0x9f, 0x98, 0x80}, true}, // emoji
		{"truncated 2-byte", []byte{0xc3}, false},
		{"invalid start byte", []byte{0xfe}, false},
		{"null bytes", []byte{0x00, 0x00}, true}, // null bytes are valid UTF-8
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidUTF8(tt.input); got != tt.valid {
				t.Errorf("IsValidUTF8(%v) = %v, want %v", tt.input, got, tt.valid)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// WriteFrame error path
// ---------------------------------------------------------------------------

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func TestWriteFrame_WriteError(t *testing.T) {
	frame := &Frame{Fin: true, Opcode: OpText, Payload: []byte("hello")}
	if err := WriteFrame(failingWriter{}, frame); err == nil {
		t.Error("expected write error")
	}
}

// ---------------------------------------------------------------------------
// getClientIP edge cases
// ---------------------------------------------------------------------------

func TestGetClientIP_IPv6(t *testing.T) {
	req := &http.Request{RemoteAddr: "[::1]:1234"}
	ip := getClientIP(req)
	if ip != "::1" {
		t.Errorf("getClientIP([::1]:1234) = %q, want ::1", ip)
	}
}

func TestGetClientIP_NoPort(t *testing.T) {
	req := &http.Request{RemoteAddr: "10.0.0.1"}
	ip := getClientIP(req)
	if ip != "10.0.0.1" {
		t.Errorf("getClientIP(10.0.0.1) = %q, want 10.0.0.1", ip)
	}
}

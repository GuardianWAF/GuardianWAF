package websocket

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestFrameReader_TextFrame(t *testing.T) {
	// 0x81 0x05 + "hello" = FIN text frame, payload "hello"
	data := []byte{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'}
	fr := NewFrameReader(bytes.NewReader(data), 1<<20)
	frame, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !frame.FIN {
		t.Error("expected FIN=true")
	}
	if frame.Opcode != OpText {
		t.Errorf("opcode = %d, want OpText(1)", frame.Opcode)
	}
	if string(frame.Payload) != "hello" {
		t.Errorf("payload = %q, want %q", frame.Payload, "hello")
	}
}

func TestFrameReader_EmptyPayload(t *testing.T) {
	data := []byte{0x81, 0x00} // empty text frame
	fr := NewFrameReader(bytes.NewReader(data), 1<<20)
	frame, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if len(frame.Payload) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(frame.Payload))
	}
}

func TestFrameReader_ExtendedLength16(t *testing.T) {
	// Payload of 300 bytes (requires 16-bit extended length).
	payload := bytes.Repeat([]byte{'A'}, 300)
	var buf bytes.Buffer
	buf.WriteByte(0x81)
	buf.WriteByte(126) // 126 = 16-bit length follows
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, 300)
	buf.Write(lenBytes)
	buf.Write(payload)

	fr := NewFrameReader(&buf, 1<<20)
	frame, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if len(frame.Payload) != 300 {
		t.Errorf("payload length = %d, want 300", len(frame.Payload))
	}
}

func TestFrameReader_FrameTooLarge(t *testing.T) {
	// Declare max size of 10, but payload says 20.
	data := []byte{0x81, 20}
	data = append(data, make([]byte, 20)...)
	fr := NewFrameReader(bytes.NewReader(data), 10)
	_, err := fr.ReadFrame()
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("expected ErrFrameTooLarge, got %v", err)
	}
}

func TestFrameReader_CloseFrame(t *testing.T) {
	// Close frame with code 1000 and no reason.
	data := []byte{0x88, 0x02, 0x03, 0xE8} // 1000 = 0x03E8
	fr := NewFrameReader(bytes.NewReader(data), 1<<20)
	frame, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if frame.Opcode != OpClose {
		t.Errorf("opcode = %d, want OpClose(8)", frame.Opcode)
	}
}

func TestFrameReader_PingFrame(t *testing.T) {
	data := []byte{0x89, 0x00}
	fr := NewFrameReader(bytes.NewReader(data), 1<<20)
	frame, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if frame.Opcode != OpPing {
		t.Errorf("opcode = %d, want OpPing(9)", frame.Opcode)
	}
	if !frame.Opcode.IsControl() {
		t.Error("ping should be control frame")
	}
}

func TestWriteFrame_RoundTrip(t *testing.T) {
	original := &Frame{
		FIN:     true,
		Opcode:  OpText,
		Payload: []byte("round trip test"),
	}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, original); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	fr := NewFrameReader(&buf, 1<<20)
	frame, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if string(frame.Payload) != "round trip test" {
		t.Errorf("payload mismatch: %q", frame.Payload)
	}
}

func TestWriteFrame_NilFrame(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, nil); err == nil {
		t.Error("expected error for nil frame")
	}
}

func TestOpcodeIsData(t *testing.T) {
	if !OpText.IsData() {
		t.Error("OpText should be data")
	}
	if !OpBinary.IsData() {
		t.Error("OpBinary should be data")
	}
	if OpPing.IsData() {
		t.Error("OpPing should not be data")
	}
}

func TestOpcodeIsControl(t *testing.T) {
	if !OpClose.IsControl() {
		t.Error("OpClose should be control")
	}
	if !OpPing.IsControl() {
		t.Error("OpPing should be control")
	}
	if !OpPong.IsControl() {
		t.Error("OpPong should be control")
	}
	if OpText.IsControl() {
		t.Error("OpText should not be control")
	}
}

func TestIsUpgradeRequest(t *testing.T) {
	tests := []struct {
		name     string
		headers  http.Header
		expected bool
	}{
		{
			name: "valid WS upgrade",
			headers: http.Header{
				"Connection": {"Upgrade"},
				"Upgrade":    {"websocket"},
			},
			expected: true,
		},
		{
			name: "lowercase upgrade",
			headers: http.Header{
				"Connection": {"upgrade"},
				"Upgrade":    {"WebSocket"},
			},
			expected: true,
		},
		{
			name: "connection has other tokens",
			headers: http.Header{
				"Connection": {"keep-alive, Upgrade"},
				"Upgrade":    {"websocket"},
			},
			expected: true,
		},
		{
			name: "missing connection upgrade",
			headers: http.Header{
				"Connection": {"keep-alive"},
				"Upgrade":    {"websocket"},
			},
			expected: false,
		},
		{
			name: "missing upgrade header",
			headers: http.Header{
				"Connection": {"Upgrade"},
			},
			expected: false,
		},
		{
			name:     "no headers",
			headers:  http.Header{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{Header: tt.headers}
			if got := IsUpgradeRequest(req); got != tt.expected {
				t.Errorf("IsUpgradeRequest = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestOriginAllowed(t *testing.T) {
	allowed := []string{"https://app.example.com", "https://trusted.test"}

	if !originAllowed("https://app.example.com", allowed) {
		t.Error("exact origin should be allowed")
	}
	if !originAllowed("https://trusted.test", allowed) {
		t.Error("second origin should be allowed")
	}
	if originAllowed("https://evil.com", allowed) {
		t.Error("untrusted origin should be rejected")
	}
	if !originAllowed("https://anything.com", []string{"*"}) {
		t.Error("wildcard should allow all origins")
	}
}

func TestLayer_ConcurrentConnections(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:            true,
		ScanPayloads:       true,
		MaxConcurrentPerIP: 2,
	})

	ip := "192.168.1.1"

	// Acquire 2 — should succeed.
	if !layer.acquireConn(ip) {
		t.Error("first acquire failed")
	}
	if !layer.acquireConn(ip) {
		t.Error("second acquire failed")
	}
	// Third should fail (limit reached).
	if layer.acquireConn(ip) {
		t.Error("third acquire should fail (limit reached)")
	}

	// Release one.
	layer.releaseConn(ip)

	// Now should succeed.
	if !layer.acquireConn(ip) {
		t.Error("acquire after release failed")
	}

	// Clean up.
	layer.releaseConn(ip)
	layer.releaseConn(ip)
}

func TestLayer_ActiveConnections(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:      true,
		ScanPayloads: true,
	})
	if layer.ActiveConnections() != 0 {
		t.Errorf("initial active conns = %d, want 0", layer.ActiveConnections())
	}
}

func TestMakeClosePayload(t *testing.T) {
	payload := makeClosePayload(1008, "policy violation")
	if len(payload) != 2+16 {
		t.Errorf("payload length = %d, want 18", len(payload))
	}
	code := int(payload[0])<<8 | int(payload[1])
	if code != 1008 {
		t.Errorf("close code = %d, want 1008", code)
	}
	if string(payload[2:]) != "policy violation" {
		t.Errorf("close reason = %q, want %q", payload[2:], "policy violation")
	}
}

func TestNewLayer_Defaults(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:      true,
		ScanPayloads: true,
		// MaxFrameSize and IdleTimeout left at zero.
	})
	if layer.cfg.MaxFrameSize != 1<<20 {
		t.Errorf("default MaxFrameSize = %d, want %d", layer.cfg.MaxFrameSize, 1<<20)
	}
	if layer.cfg.IdleTimeout != 60*time.Second {
		t.Errorf("default IdleTimeout = %v, want 60s", layer.cfg.IdleTimeout)
	}
}

func TestLayer_Wrap_NonWebSocket(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	layer := NewLayer(&Config{
		Enabled:      true,
		ScanPayloads: true,
	})
	wrapped := layer.Wrap(next)

	req, _ := http.NewRequest("GET", "/api/data", nil)
	req.Header.Set("Connection", "keep-alive")
	rec := &mockResponseWriter{header: http.Header{}}
	wrapped.ServeHTTP(rec, req)

	if !called {
		t.Error("next handler should be called for non-WS request")
	}
}

func TestLayer_Wrap_Disabled(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	// Disabled layer should pass through directly.
	layer := NewLayer(&Config{Enabled: false})
	wrapped := layer.Wrap(next)
	// Wrap returns next unchanged when disabled.
	handlerFunc, ok := wrapped.(http.HandlerFunc)
	if !ok || fmt.Sprintf("%p", handlerFunc) != fmt.Sprintf("%p", next) {
		t.Error("disabled layer should return next unchanged")
	}
}

// mockResponseWriter implements http.ResponseWriter for testing.
type mockResponseWriter struct {
	header     http.Header
	statusCode int
	body       bytes.Buffer
}

func (m *mockResponseWriter) Header() http.Header {
	if m.header == nil {
		m.header = http.Header{}
	}
	return m.header
}

func (m *mockResponseWriter) Write(b []byte) (int, error) {
	return m.body.Write(b)
}

func (m *mockResponseWriter) WriteHeader(code int) {
	m.statusCode = code
}

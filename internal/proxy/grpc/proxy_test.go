package grpc

import (
	"bytes"
	"encoding/binary"
	"net/http/httptest"
	"testing"
)

func TestIsGRPCRequest(t *testing.T) {
	tests := []struct {
		name      string
		contentType string
		expected  bool
	}{
		{
			name:      "gRPC request",
			contentType: "application/grpc",
			expected:  true,
		},
		{
			name:      "gRPC-Web request",
			contentType: "application/grpc-web",
			expected:  true,
		},
		{
			name:      "gRPC with charset",
			contentType: "application/grpc; charset=utf-8",
			expected:  true,
		},
		{
			name:      "regular JSON",
			contentType: "application/json",
			expected:  false,
		},
		{
			name:      "empty content type",
			contentType: "",
			expected:  false,
		},
		{
			name:      "protobuf",
			contentType: "application/x-protobuf",
			expected:  false, // Not a gRPC content type
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", nil)
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			result := IsGRPCRequest(req)
			if result != tt.expected {
				t.Errorf("IsGRPCRequest() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsGRPCWeb(t *testing.T) {
	tests := []struct {
		name      string
		contentType string
		expected  bool
	}{
		{
			name:      "gRPC-Web",
			contentType: "application/grpc-web",
			expected:  true,
		},
		{
			name:      "gRPC-Web text",
			contentType: "application/grpc-web-text",
			expected:  true,
		},
		{
			name:      "gRPC",
			contentType: "application/grpc",
			expected:  false,
		},
		{
			name:      "regular request",
			contentType: "application/json",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", nil)
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			result := IsGRPCWeb(req)
			if result != tt.expected {
				t.Errorf("IsGRPCWeb() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestNewProxy(t *testing.T) {
	cfg := &Config{
		Enabled:        true,
		GRPCWebEnabled: true,
		MaxMessageSize: 1024 * 1024,
		ProtoPaths:     []string{}, // Empty for test
	}

	proxy, err := NewProxy(cfg)
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}

	if proxy == nil {
		t.Fatal("expected proxy, got nil")
	}

	if !proxy.grpcWebEnabled {
		t.Error("grpcWebEnabled should be true")
	}
}

func TestProxy_CanHandle(t *testing.T) {
	cfg := DefaultConfig()
	proxy, err := NewProxy(&cfg)
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}

	tests := []struct {
		name      string
		contentType string
		expected  bool
	}{
		{
			name:      "gRPC request",
			contentType: "application/grpc",
			expected:  true,
		},
		{
			name:      "gRPC-Web request",
			contentType: "application/grpc-web",
			expected:  true,
		},
		{
			name:      "HTTP JSON",
			contentType: "application/json",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", nil)
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			result := proxy.CanHandle(req)
			if result != tt.expected {
				t.Errorf("CanHandle() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestExtractMethodName(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{
			path:     "/package.service/Method",
			expected: "Method",
		},
		{
			path:     "/com.example.UserService/GetUser",
			expected: "GetUser",
		},
		{
			path:     "/Method",
			expected: "/Method", // Single segment returns as-is
		},
		{
			path:     "/",
			expected: "/",
		},
		{
			path:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := extractMethodName(tt.path)
			if result != tt.expected {
				t.Errorf("extractMethodName(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func TestParseGRPCFrames(t *testing.T) {
	// Build a simple gRPC frame
	message := []byte("hello world")
	frame := make([]byte, 5+len(message))
	frame[0] = 0 // Not compressed
	binary.BigEndian.PutUint32(frame[1:], uint32(len(message)))
	copy(frame[5:], message)

	messages, err := parseGRPCFrames(frame)
	if err != nil {
		t.Fatalf("parseGRPCFrames failed: %v", err)
	}

	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}

	if !bytes.Equal(messages[0], message) {
		t.Errorf("message mismatch: got %q, want %q", messages[0], message)
	}
}

func TestParseGRPCFrames_Multiple(t *testing.T) {
	// Build multiple frames
	msg1 := []byte("first")
	msg2 := []byte("second")

	frame := make([]byte, 10+len(msg1)+len(msg2))
	offset := 0

	// First message
	frame[offset] = 0
	binary.BigEndian.PutUint32(frame[offset+1:], uint32(len(msg1)))
	copy(frame[offset+5:], msg1)
	offset += 5 + len(msg1)

	// Second message
	frame[offset] = 0
	binary.BigEndian.PutUint32(frame[offset+1:], uint32(len(msg2)))
	copy(frame[offset+5:], msg2)

	messages, err := parseGRPCFrames(frame)
	if err != nil {
		t.Fatalf("parseGRPCFrames failed: %v", err)
	}

	if len(messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(messages))
	}

	if !bytes.Equal(messages[0], msg1) {
		t.Errorf("first message mismatch: got %q, want %q", messages[0], msg1)
	}
	if !bytes.Equal(messages[1], msg2) {
		t.Errorf("second message mismatch: got %q, want %q", messages[1], msg2)
	}
}

func TestProxy_isMethodAllowed(t *testing.T) {
	tests := []struct {
		name       string
		allowed    []string
		blocked    []string
		method     string
		shouldPass bool
	}{
		{
			name:       "no ACL - allow all",
			allowed:    []string{},
			blocked:    []string{},
			method:     "GetUser",
			shouldPass: true,
		},
		{
			name:       "whitelist - allowed",
			allowed:    []string{"GetUser", "CreateUser"},
			blocked:    []string{},
			method:     "GetUser",
			shouldPass: true,
		},
		{
			name:       "whitelist - not allowed",
			allowed:    []string{"GetUser"},
			blocked:    []string{},
			method:     "DeleteUser",
			shouldPass: false,
		},
		{
			name:       "blocked list",
			allowed:    []string{},
			blocked:    []string{"DeleteUser"},
			method:     "DeleteUser",
			shouldPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Enabled:        true,
				AllowedMethods: tt.allowed,
				BlockedMethods: tt.blocked,
			}

			proxy, err := NewProxy(cfg)
			if err != nil {
				t.Fatalf("NewProxy failed: %v", err)
			}

			result := proxy.isMethodAllowed(tt.method)
			if result != tt.shouldPass {
				t.Errorf("isMethodAllowed(%q) = %v, want %v", tt.method, result, tt.shouldPass)
			}
		})
	}
}

func TestValidator_ValidateMessage(t *testing.T) {
	v, err := NewValidator([]string{})
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "empty message",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "valid message",
			data:    []byte("hello"),
			wantErr: false,
		},
		{
			name:    "large message",
			data:    make([]byte, 5*1024*1024), // 5MB
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateMessage("TestMethod", tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateMessage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("Enabled should be false by default")
	}
	if !cfg.GRPCWebEnabled {
		t.Error("GRPCWebEnabled should be true by default")
	}
	if cfg.MaxMessageSize != 4*1024*1024 {
		t.Errorf("MaxMessageSize = %d, want %d", cfg.MaxMessageSize, 4*1024*1024)
	}
}

func TestProxy_Stats(t *testing.T) {
	cfg := DefaultConfig()
	proxy, err := NewProxy(&cfg)
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}

	// Record some stats
	proxy.recordTraffic(100, 50)
	proxy.recordTraffic(200, 100)

	stats := proxy.Stats()

	if stats.RPCCount != 2 {
		t.Errorf("RPCCount = %d, want 2", stats.RPCCount)
	}
	if stats.BytesOut != 300 {
		t.Errorf("BytesOut = %d, want 300", stats.BytesOut)
	}
	if stats.BytesIn != 150 {
		t.Errorf("BytesIn = %d, want 150", stats.BytesIn)
	}
}

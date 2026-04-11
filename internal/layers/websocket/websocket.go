// Package websocket provides WebSocket security for GuardianWAF.
package websocket

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	// WebSocket GUID for handshake
	websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

	// Frame opcodes
	OpContinuation = 0x0
	OpText         = 0x1
	OpBinary       = 0x2
	OpClose        = 0x8
	OpPing         = 0x9
	OpPong         = 0xA
)

// Config for WebSocket security.
type Config struct {
	Enabled              bool          `yaml:"enabled"`
	MaxMessageSize       int64         `yaml:"max_message_size"`
	MaxFrameSize         int64         `yaml:"max_frame_size"`
	RateLimitPerSecond   int           `yaml:"rate_limit_per_second"`
	RateLimitBurst       int           `yaml:"rate_limit_burst"`
	AllowedOrigins       []string      `yaml:"allowed_origins"`
	BlockedExtensions    []string      `yaml:"blocked_extensions"`
	BlockEmptyMessages   bool          `yaml:"block_empty_messages"`
	BlockBinaryMessages  bool          `yaml:"block_binary_messages"`
	MaxConcurrentPerIP   int           `yaml:"max_concurrent_per_ip"`
	HandshakeTimeout     time.Duration `yaml:"handshake_timeout"`
	IdleTimeout          time.Duration `yaml:"idle_timeout"`
	ScanPayloads         bool          `yaml:"scan_payloads"`
}

// DefaultConfig returns default WebSocket config.
func DefaultConfig() *Config {
	return &Config{
		Enabled:             true,
		MaxMessageSize:      10 * 1024 * 1024, // 10MB
		MaxFrameSize:        1 * 1024 * 1024,  // 1MB
		RateLimitPerSecond:  100,
		RateLimitBurst:      50,
		AllowedOrigins:      []string{}, // Empty = same-origin policy (cross-origin requires explicit config)
		BlockedExtensions:   []string{},
		BlockEmptyMessages:  false,
		BlockBinaryMessages: false,
		MaxConcurrentPerIP:  100,
		HandshakeTimeout:    10 * time.Second,
		IdleTimeout:         60 * time.Second,
		ScanPayloads:        true,
	}
}

// Frame represents a WebSocket frame.
type Frame struct {
	Fin        bool
	Rsv1       bool
	Rsv2       bool
	Rsv3       bool
	Opcode     byte
	Masked     bool
	MaskKey    [4]byte
	Payload    []byte
	PayloadLen uint64
}

// IsControl returns true if the frame is a control frame.
func (f *Frame) IsControl() bool {
	return f.Opcode >= 0x8
}

// IsData returns true if the frame is a data frame.
func (f *Frame) IsData() bool {
	return f.Opcode < 0x8
}

// Connection tracks WebSocket connection state.
type Connection struct {
	ID         string
	RemoteAddr string
	Origin     string
	Path       string
	Connected  time.Time
	LastSeen   time.Time
	MsgCount   int64
	ByteCount  int64
	RateLimiter *RateLimiter
	mu         sync.RWMutex
}

// RateLimiter implements token bucket rate limiting.
type RateLimiter struct {
	tokens   float64
	burst    float64
	rate     float64
	lastTime time.Time
	mu       sync.Mutex
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(rate, burst int) *RateLimiter {
	return &RateLimiter{
		tokens:   float64(burst),
		burst:    float64(burst),
		rate:     float64(rate),
		lastTime: time.Now(),
	}
}

// Allow checks if a message should be allowed.
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastTime).Seconds()
	rl.lastTime = now

	// Add tokens based on elapsed time
	rl.tokens += elapsed * rl.rate
	if rl.tokens > rl.burst {
		rl.tokens = rl.burst
	}

	if rl.tokens >= 1 {
		rl.tokens--
		return true
	}
	return false
}

// Security provides WebSocket security functionality.
type Security struct {
	config      *Config
	connections map[string]*Connection
	connMu      sync.RWMutex
	stopCh      chan struct{}
	wg          sync.WaitGroup
}

// NewSecurity creates a new WebSocket security instance.
func NewSecurity(cfg *Config) (*Security, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	s := &Security{
		config:      cfg,
		connections: make(map[string]*Connection),
		stopCh:      make(chan struct{}),
	}

	// Start cleanup routine
	s.wg.Add(1)
	go s.cleanupLoop()

	return s, nil
}

// ValidateHandshake validates the WebSocket upgrade request.
func (s *Security) ValidateHandshake(r *http.Request) error {
	if !s.config.Enabled {
		return nil
	}

	// Check if this is a WebSocket upgrade request
	if !isWebSocketUpgrade(r) {
		return fmt.Errorf("not a WebSocket upgrade request")
	}

	// Check origin if allowed origins configured
	if len(s.config.AllowedOrigins) > 0 {
		origin := r.Header.Get("Origin")
		if !s.isAllowedOrigin(origin, r) {
			return fmt.Errorf("origin not allowed: %s", origin)
		}
	}

	// Check path extension
	if s.isBlockedExtension(r.URL.Path) {
		return fmt.Errorf("blocked extension in path: %s", r.URL.Path)
	}

	// Validate WebSocket key
	wsKey := r.Header.Get("Sec-Websocket-Key")
	if wsKey == "" {
		return fmt.Errorf("missing Sec-WebSocket-Key header")
	}

	// Check connection limit per IP
	if s.config.MaxConcurrentPerIP > 0 {
		ip := getClientIP(r)
		if s.getConnectionCountForIP(ip) >= s.config.MaxConcurrentPerIP {
			return fmt.Errorf("max concurrent connections reached for IP: %s", ip)
		}
	}

	return nil
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	connection := strings.ToLower(r.Header.Get("Connection"))
	return upgrade == "websocket" && strings.Contains(connection, "upgrade")
}

// isAllowedOrigin checks if the origin is in the allowed list.
// When no allowed origins are configured, defaults to same-origin policy.
func (s *Security) isAllowedOrigin(origin string, r *http.Request) bool {
	if len(s.config.AllowedOrigins) == 0 {
		// Default to same-origin policy: reject cross-origin entirely
		if origin == "" {
			return true // No Origin header (same-origin browser request)
		}
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return u.Host == r.Host
	}

	for _, allowed := range s.config.AllowedOrigins {
		if allowed == origin {
			return true
		}
		// Support wildcard subdomains (e.g., https://*.example.com or *.example.com)
		if strings.Contains(allowed, "*.") {
			// Split pattern and origin by :// to separate scheme and host
			allowedParts := strings.SplitN(allowed, "://", 2)
			originParts := strings.SplitN(origin, "://", 2)

			// If schemes are specified and don't match, skip
			if len(allowedParts) == 2 && len(originParts) == 2 {
				if allowedParts[0] != originParts[0] {
					continue
				}
			}

			// Get the pattern after *.
			patternHost := allowedParts[len(allowedParts)-1]
			originHost := originParts[len(originParts)-1]

			if strings.HasPrefix(patternHost, "*.") {
				suffix := patternHost[1:] // Remove * to get .example.com
				if strings.HasSuffix(originHost, suffix) {
					return true
				}
			}
		}
	}
	return false
}

// isBlockedExtension checks if the path has a blocked extension.
func (s *Security) isBlockedExtension(path string) bool {
	for _, ext := range s.config.BlockedExtensions {
		if strings.HasSuffix(strings.ToLower(path), strings.ToLower(ext)) {
			return true
		}
	}
	return false
}

// getConnectionCountForIP returns the number of connections for an IP.
func (s *Security) getConnectionCountForIP(ip string) int {
	s.connMu.RLock()
	defer s.connMu.RUnlock()

	count := 0
	for _, conn := range s.connections {
		if conn.RemoteAddr == ip {
			count++
		}
	}
	return count
}

// RegisterConnection registers a new WebSocket connection.
func (s *Security) RegisterConnection(id, remoteAddr, origin, path string) *Connection {
	conn := &Connection{
		ID:          id,
		RemoteAddr:  remoteAddr,
		Origin:      origin,
		Path:        path,
		Connected:   time.Now(),
		LastSeen:    time.Now(),
		RateLimiter: NewRateLimiter(s.config.RateLimitPerSecond, s.config.RateLimitBurst),
	}

	s.connMu.Lock()
	s.connections[id] = conn
	s.connMu.Unlock()

	log.Printf("[websocket] New connection: %s from %s", id, remoteAddr)
	return conn
}

// UnregisterConnection removes a connection.
func (s *Security) UnregisterConnection(id string) {
	s.connMu.Lock()
	delete(s.connections, id)
	s.connMu.Unlock()

	log.Printf("[websocket] Connection closed: %s", id)
}

// GetConnection returns a connection by ID.
func (s *Security) GetConnection(id string) *Connection {
	s.connMu.RLock()
	conn := s.connections[id]
	s.connMu.RUnlock()
	return conn
}

// GetAllConnections returns all connections.
func (s *Security) GetAllConnections() []*Connection {
	s.connMu.RLock()
	conns := make([]*Connection, 0, len(s.connections))
	for _, conn := range s.connections {
		conns = append(conns, conn)
	}
	s.connMu.RUnlock()
	return conns
}

// ValidateFrame validates an incoming WebSocket frame.
func (s *Security) ValidateFrame(conn *Connection, frame *Frame) error {
	if !s.config.Enabled {
		return nil
	}

	// Update connection stats
	conn.mu.Lock()
	conn.LastSeen = time.Now()
	conn.MsgCount++
	conn.ByteCount += int64(len(frame.Payload))
	conn.mu.Unlock()

	// Check rate limit
	if !conn.RateLimiter.Allow() {
		return fmt.Errorf("rate limit exceeded")
	}

	// Check frame size
	if s.config.MaxFrameSize > 0 && int64(len(frame.Payload)) > s.config.MaxFrameSize {
		return fmt.Errorf("frame too large: %d bytes", len(frame.Payload))
	}

	// Check total message size for data frames
	if frame.IsData() && s.config.MaxMessageSize > 0 {
		// This is simplified - in production you'd track fragmented messages
		if int64(len(frame.Payload)) > s.config.MaxMessageSize {
			return fmt.Errorf("message too large: %d bytes", len(frame.Payload))
		}
	}

	// Check empty messages
	if s.config.BlockEmptyMessages && len(frame.Payload) == 0 && frame.IsData() {
		return fmt.Errorf("empty message not allowed")
	}

	// Check binary messages
	if s.config.BlockBinaryMessages && frame.Opcode == OpBinary {
		return fmt.Errorf("binary messages not allowed")
	}

	// Scan payload for threats if enabled
	if s.config.ScanPayloads && frame.Opcode == OpText && len(frame.Payload) > 0 {
		if threat := s.scanPayload(frame.Payload); threat != "" {
			return fmt.Errorf("threat detected in payload: %s", threat)
		}
	}

	return nil
}

// scanPayload scans payload for common threats.
// orderedPattern defines a pattern with its threat type and priority.
type orderedPattern struct {
	pattern string
	threat  string
}

// patterns is ordered by specificity - more specific patterns first.
var patterns = []orderedPattern{
	// Log4j before general template injection
	{"${jndi:", "log4j"},
	{"${", "template_injection"},
	// XSS patterns
	{"<script", "xss"},
	{"javascript:", "xss"},
	{"onerror=", "xss"},
	{"onload=", "xss"},
	// SQL injection
	{"select ", "sqli"},
	{"insert ", "sqli"},
	{"update ", "sqli"},
	{"delete ", "sqli"},
	{"drop ", "sqli"},
	{"union ", "sqli"},
	// Path traversal
	{"../", "path_traversal"},
	{"..\\", "path_traversal"},
	// LFI
	{"/etc/passwd", "lfi"},
	{"c:\\windows\\system32", "lfi"},
	// Prototype pollution
	{"__proto__", "prototype_pollution"},
	{"constructor", "prototype_pollution"},
}

func (s *Security) scanPayload(payload []byte) string {
	payloadStr := string(payload)
	lowerPayload := strings.ToLower(payloadStr)

	for _, p := range patterns {
		if strings.Contains(lowerPayload, p.pattern) {
			return p.threat
		}
	}

	return ""
}

// ParseFrame parses a WebSocket frame from the reader.
func ParseFrame(r io.Reader) (*Frame, error) {
	br := bufio.NewReader(r)

	// Read first byte (FIN, RSV, Opcode)
	b1, err := br.ReadByte()
	if err != nil {
		return nil, err
	}

	frame := &Frame{
		Fin:    (b1 & 0x80) != 0,
		Rsv1:   (b1 & 0x40) != 0,
		Rsv2:   (b1 & 0x20) != 0,
		Rsv3:   (b1 & 0x10) != 0,
		Opcode: b1 & 0x0F,
	}

	// Read second byte (MASK, Payload length)
	b2, err := br.ReadByte()
	if err != nil {
		return nil, err
	}

	frame.Masked = (b2 & 0x80) != 0
	payloadLen := uint64(b2 & 0x7F)

	// Handle extended payload length
	switch payloadLen {
	case 126:
		var extendedLen uint16
		if err := binary.Read(br, binary.BigEndian, &extendedLen); err != nil {
			return nil, err
		}
		payloadLen = uint64(extendedLen)
	case 127:
		if err := binary.Read(br, binary.BigEndian, &payloadLen); err != nil {
			return nil, err
		}
	}

	frame.PayloadLen = payloadLen

	// Guard against OOM: reject frames claiming payloads larger than 16MB
	const maxFramePayload = 16 * 1024 * 1024
	if payloadLen > maxFramePayload {
		return nil, fmt.Errorf("frame payload too large: %d bytes (max %d)", payloadLen, maxFramePayload)
	}

	// Read mask key if present
	if frame.Masked {
		if _, err := io.ReadFull(br, frame.MaskKey[:]); err != nil {
			return nil, err
		}
	}

	// Read payload
	if payloadLen > 0 {
		frame.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(br, frame.Payload); err != nil {
			return nil, err
		}

		// Unmask payload
		if frame.Masked {
			for i := range frame.Payload {
				frame.Payload[i] ^= frame.MaskKey[i%4]
			}
		}
	}

	return frame, nil
}

// GenerateAcceptKey generates the Sec-WebSocket-Accept key per RFC 6455 Section 4.2.2.
// Uses SHA-1 as mandated by the WebSocket protocol specification.
func GenerateAcceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key + websocketGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// cleanupLoop periodically cleans up stale connections.
func (s *Security) cleanupLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.CleanupStaleConnections()
		case <-s.stopCh:
			return
		}
	}
}

// CleanupStaleConnections removes idle connections (public for testing).
func (s *Security) CleanupStaleConnections() {
	if s.config.IdleTimeout <= 0 {
		return
	}

	s.connMu.Lock()
	defer s.connMu.Unlock()

	now := time.Now()
	for id, conn := range s.connections {
		conn.mu.RLock()
		lastSeen := conn.LastSeen
		conn.mu.RUnlock()

		if now.Sub(lastSeen) > s.config.IdleTimeout {
			delete(s.connections, id)
			log.Printf("[websocket] Cleaned up idle connection: %s", id)
		}
	}
}

// GetStats returns connection statistics.
func (s *Security) GetStats() Stats {
	s.connMu.RLock()
	defer s.connMu.RUnlock()

	stats := Stats{
		ActiveConnections: len(s.connections),
	}

	for _, conn := range s.connections {
		conn.mu.RLock()
		stats.TotalMessages += conn.MsgCount
		stats.TotalBytes += conn.ByteCount
		conn.mu.RUnlock()
	}

	return stats
}

// Stop stops the WebSocket security.
func (s *Security) Stop() {
	select {
	case <-s.stopCh:
		return
	default:
		close(s.stopCh)
	}
	s.wg.Wait()
}

// Stats holds WebSocket statistics.
type Stats struct {
	ActiveConnections int   `json:"active_connections"`
	TotalMessages     int64 `json:"total_messages"`
	TotalBytes        int64 `json:"total_bytes"`
}

// Helper functions

func getClientIP(r *http.Request) string {
	// NOTE: We intentionally do NOT trust X-Forwarded-For or X-Real-Ip here
	// because this layer has no access to the trusted proxy configuration.
	// Trusting unvalidated proxy headers allows trivial IP spoofing for
	// MaxConcurrentPerIP bypass. If deployed behind a trusted proxy, the
	// proxy should set a fixed header (e.g. X-Client-IP) with the real IP.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// WriteFrame writes a WebSocket frame to the writer.
func WriteFrame(w io.Writer, frame *Frame) error {
	// First byte: FIN, RSV, Opcode
	b1 := frame.Opcode
	if frame.Fin {
		b1 |= 0x80
	}
	if frame.Rsv1 {
		b1 |= 0x40
	}
	if frame.Rsv2 {
		b1 |= 0x20
	}
	if frame.Rsv3 {
		b1 |= 0x10
	}

	if err := writeByte(w, b1); err != nil {
		return err
	}

	// Second byte: MASK, Payload length
	payloadLen := len(frame.Payload)
	b2 := byte(0)

	if frame.Masked {
		b2 |= 0x80
	}

	if payloadLen < 126 {
		b2 |= byte(payloadLen)
		if err := writeByte(w, b2); err != nil {
			return err
		}
	} else if payloadLen < 65536 {
		b2 |= 126
		if err := writeByte(w, b2); err != nil {
			return err
		}
		if err := binary.Write(w, binary.BigEndian, uint16(payloadLen)); err != nil {
			return err
		}
	} else {
		b2 |= 127
		if err := writeByte(w, b2); err != nil {
			return err
		}
		if err := binary.Write(w, binary.BigEndian, uint64(payloadLen)); err != nil {
			return err
		}
	}

	// Write mask key if present
	if frame.Masked {
		if _, err := w.Write(frame.MaskKey[:]); err != nil {
			return err
		}
	}

	// Write payload (mask if needed)
	if payloadLen > 0 {
		payload := frame.Payload
		if frame.Masked {
			payload = make([]byte, payloadLen)
			for i := range frame.Payload {
				payload[i] = frame.Payload[i] ^ frame.MaskKey[i%4]
			}
		}
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}

	return nil
}

func writeByte(w io.Writer, b byte) error {
	_, err := w.Write([]byte{b})
	return err
}

// CreateCloseFrame creates a close frame with optional reason.
func CreateCloseFrame(code uint16, reason string) *Frame {
	payload := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(payload, code)
	copy(payload[2:], reason)

	return &Frame{
		Fin:     true,
		Opcode:  OpClose,
		Payload: payload,
	}
}

// CreateTextFrame creates a text frame.
func CreateTextFrame(text string) *Frame {
	return &Frame{
		Fin:     true,
		Opcode:  OpText,
		Payload: []byte(text),
	}
}

// CreatePongFrame creates a pong frame in response to ping.
func CreatePongFrame(pingPayload []byte) *Frame {
	return &Frame{
		Fin:     true,
		Opcode:  OpPong,
		Payload: pingPayload,
	}
}

// IsValidUTF8 checks if payload is valid UTF-8 (required for text frames).
func IsValidUTF8(data []byte) bool {
	return utf8.Valid(data)
}
